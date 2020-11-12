module Data.Attoparsec.Network where

import Control.Monad
import Data.Attoparsec.Binary
import Data.Attoparsec.ByteString as A
import Data.Bits
import Data.ByteString (ByteString)
import Data.Data
import Data.Word
import GHC.Generics
import Network.Socket

data PacketType = IPv4 | IPv6 | PktTypeOther
                  deriving (Eq,Ord,Show)

data L4Proto = TCP | UDP
               deriving (Eq,Ord,Data,Generic,Show)


type ProtoNum = Int

newtype L4Payload = L4Payload { l4unPayload :: ByteString }
                    deriving (Eq,Ord,Show)

instance Enum L4Proto where
  fromEnum TCP   = 6
  fromEnum UDP   = 17

  toEnum 17  = UDP
  toEnum 6   = TCP

data L4Header = L4Header { l4proto :: !Int
                         , l4src   :: !SockAddr
                         , l4dst   :: !SockAddr
                         }
                deriving (Eq,Ord,Show)

data L4Packet = Packet { l4hdr  :: L4Header
                       , l4data :: L4Payload
                       }
                deriving (Eq,Ord,Show)

etherAddrLen :: Int
etherAddrLen = 6

etherTypeLen :: Int
etherTypeLen = 2

etherHdrLen :: Int
etherHdrLen = etherAddrLen * 2 + etherTypeLen

etherTypeIPv4 :: Int
etherTypeIPv4 = 0x0800

etherTypeIPv6 :: Int
etherTypeIPv6 = 0x86DD

etherTypeVLAN :: Int
etherTypeVLAN = 0x8100

skipBytes :: Int -> Parser ()
skipBytes n = A.take n >> pure ()

skipMAC :: Parser ()
skipMAC = A.take 6 *> pure ()

skipEtherHeader :: Parser PacketType
skipEtherHeader = do
  skipMAC
  skipMAC

  tpW <- anyWord16be

  tp <- case tpW of
          0x0800 -> pure IPv4
          0x86DD -> pure IPv6
          0x8100 -> skipBytes 4 *> pure PktTypeOther
          x      -> pure PktTypeOther

  return tp

-- struct iphdr {
--     __u8    ihl:4,
--             version:4;
--     __u8    tos;
--     __be16  tot_len;
--     __be16  id;
--     __be16  frag_off;
--     __u9    ttl;
--     __u8    protocol;
--     __sum16 check;
--     __be32  saddr;
--     __be32  daddr;
--     /*The options start here. */
-- };

skipIPv4HdrToAddress :: Parser (Int, Int)
skipIPv4HdrToAddress = do
  v <- anyWord8
  let ihl = v .&. 0x0F
  tos     <- anyWord8
  totLen  <- anyWord16be
  id_     <- anyWord16be
  fragOff <- anyWord16be
  ttl     <- anyWord8
  proto   <- anyWord8
  chk     <- anyWord16be
  pure $ (toEnum (fromIntegral proto), fromIntegral (ihl*4 - 20))

ipHdrAddrOnly :: PacketType -> Parser L4Header

ipHdrAddrOnly IPv4 = do
  (proto,optLen)   <- skipIPv4HdrToAddress
  saddr            <- anyWord32le
  daddr            <- anyWord32le
  skipBytes optLen
  pure $ L4Header { l4proto = proto
                  , l4src   = (SockAddrInet 0 saddr)
                  , l4dst   = (SockAddrInet 0 daddr)
                  }

ipHdrAddrOnly _ = fail "only IPv4 supported yet"


etherL4Packet :: Parser L4Packet
etherL4Packet = do
  tp   <- skipEtherHeader
  hdr  <- ipHdrAddrOnly tp
  parseL4 (l4proto hdr) hdr

  where
    parseL4 :: ProtoNum -> L4Header -> Parser L4Packet

-- struct udphdr {
--   __be16	source;
--   __be16	dest;
--   __be16	len;
--   __sum16	check;
-- };

    parseL4 proto h | proto == fromEnum UDP = do
      psrc <- anyWord16be
      pdst <- anyWord16be
      ulen <- anyWord16be
      chk  <- anyWord16be
      pl   <- takeByteString
      pure $ mkPkt h psrc pdst pl

-- struct tcphdr {
--      __be16  source;
--      __be16  dest;
--      __be32  seq;           4
--      __be32  ack_seq;       4
--      __u16   res1:4,        2
--          doff:4,
--          fin:1,
--          syn:1,
--          rst:1,
--          psh:1,
--          ack:1,
--          urg:1,
--          ece:1,
--          cwr:1;
--      __be16  window;        2
--      __sum16 check;         2
--      __be16  urg_ptr;       2
--  };

    parseL4 proto h | proto == fromEnum TCP = do
      psrc <- anyWord16be -- src_port    2
      pdst <- anyWord16be -- dst_port    4
      skipBytes 4         -- seq         8
      skipBytes 4         -- ack_seq    12
      res0 <- anyWord8    -- res8       13
      skipBytes 1         -- res8       14
      skipBytes 2 -- window             16
      skipBytes 2 -- chk                18
      skipBytes 2 -- urg                20

      let tl = res0 `shiftR` 4 -- .&. 0x0F
      skipBytes (fromIntegral $ tl*4 - 20)
      pl   <- takeByteString
      pure $ mkPkt h psrc pdst pl

    parseL4 _ _ = fail "Only TCP and UDP protocols are supported so far"

    mkSa f p h =
      let (SockAddrInet _ a) = f h in SockAddrInet (fromIntegral p) a

    mkPkt :: L4Header -> Word16 -> Word16 -> ByteString -> L4Packet
    mkPkt h p1 p2 bs = Packet h' (L4Payload bs)
      where h' = h { l4src = mkSa l4src p1 h
                   , l4dst = mkSa l4dst p2 h
                   }
