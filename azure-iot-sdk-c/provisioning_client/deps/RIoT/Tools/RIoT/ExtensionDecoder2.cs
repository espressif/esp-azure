using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
/*
 * This will be a RIoT extension decoder that doesn't use BC.
 *              INCOMPLETE
 * 
 * */



namespace RIoT
{
    internal enum DerTags
    {
        Integer = 2,
        BitString = 3,
        Sequence = 16,
        Oid = 6
    }

    internal class ExtensionDecoder2
    {
        internal ExtensionDecoder2(byte[] extension)
        {

        }
    }

    internal class DERSequence
    {
        byte[] Data;
        // this describes the data in this sequence
        int Start;
        int TotalLength;
        int PayloadStart;
        int PayloadLength;
        int EndPointer;
        // This is 
        int ParsePointer;

        internal DERSequence(byte[] _x, int _start)
        {
            Data = _x;
            Start = _start;
            ParsePointer = Start;
            if (Data[ParsePointer++] != (byte)DerTags.Sequence)
            {
                throw new Exception($"Not a sequence: start = {Start}");
            }
            PayloadLength = GetDEREncodedInt();
            PayloadStart = ParsePointer;
            //TotalLength = PayloadLength + headerLength;
            EndPointer = Start + TotalLength;
            if (Start + TotalLength > Data.Length) throw new Exception($"Sequence length of {PayloadLength}, but only {Data.Length - Start}");
        }
        internal DERSequence GetSequence()
        {
            var s = new DERSequence(Data, ParsePointer);
            ParsePointer += s.TotalLength;
            return s;
        }
        internal int GetShortInt()
        {
            var tag = (byte)Data[ParsePointer++];
            if (tag != (byte)DerTags.Integer) throw new Exception($"Integer tag expected at {ParsePointer}");
            int dataLen = GetDEREncodedInt();
            if (dataLen > 1) throw new NotImplementedException();
            return (int)Data[ParsePointer++];
        }
        internal int GetOctetString()
        {
            var tag = (byte)Data[ParsePointer++];
            if (tag != (byte)DerTags.Integer) throw new Exception($"Integer tag expected at {ParsePointer}");
            int dataLen = GetDEREncodedInt();
            if (dataLen > 1) throw new NotImplementedException();
            return (int)Data[ParsePointer++];
        }


        internal int GetOID()
        {
            var tag = Data[ParsePointer++];
            if (tag != (byte)DerTags.Oid) throw new Exception($"OID tag expected at {ParsePointer}");
            int intLen = GetDEREncodedInt();
            ParsePointer += intLen;
            return 0;
        }
        private int GetDEREncodedInt()
        {
            if (ParsePointer >= EndPointer) throw new Exception("overflow");
            uint n = (uint)Data[ParsePointer++];
            // if n<127, then it's the length
            if (n < 127) return (int)n;
            // if n>127 then it's the number of bytes.  We only care about
            // small numbers
            if (n == 1)
            {
                if (ParsePointer >= EndPointer) throw new Exception("e2");
                return (int)Data[ParsePointer++];
            }
            if (n == 2)
            {
                if (ParsePointer >= EndPointer) throw new Exception("e2");
                int t = Data[ParsePointer++] * 256;
                if (ParsePointer >= EndPointer) throw new Exception("e2");
                return t + Data[ParsePointer++];
            }

            throw new Exception("Number too big");
        }


    }
/*
    internal class DerHeader
    {
        // todo - sequence overflow
        internal static int GetLength(byte[] x, int pos)
        {
            uint n = (uint)x[pos];
            // if n<127, then it's the length
            if (n < 127) return (int)n;
            // if n>127 then it's the number of bytes.  We only care about
            // small numbers
            if (n == 1) return (int)x[pos + 1];
            if (n == 2) return x[pos + 1] * 256 + x[pos + 2];
            throw new Exception("Number too big");
        }
        internal static int GetLengthLength(byte[] x, int pos)
        {
            uint n = (uint)x[pos];
            if (n < 127) return 1;
            return (int)n + 1;
        }

    }
    */
}
