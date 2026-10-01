using System.Numerics;
using Org.BouncyCastle.Math.EC.Rfc7748;
using Org.BouncyCastle.Security;

namespace Dp9ik;

/// <summary>
/// The AuthPAK curve arithmetic of 9front libauthsrv, transcribed from ed448.mp, edwards.mp,
/// decaf.mp, elligator2.mp, spake2ee.mp and msqrt.mp. Field arithmetic uses BouncyCastle's
/// constant-time X448Field; the scalar multiplication is a fixed-length ladder with constant-time
/// selection, as edwards_scale is. Values cross this boundary as 56-byte big-endian integers,
/// matching mptober.
/// </summary>
internal static class AuthPakCurve
{
    internal const int Size = Dp9ikConstants.PakScalarLength;

    // x^2+y^2 = 1-39081x^2y^2 over p = 2^448 - 2^224 - 1 (ed448.mp).
    internal static readonly BigInteger P = BigInteger.Pow(2, 448) - BigInteger.Pow(2, 224) - 1;
    internal static readonly BigInteger HalfP = (P - 1) / 2;
    private static readonly BigInteger GeneratorX = BigInteger.Parse(
        "117812161263436946737282484343310064665180535357016373416879082147939404277809514858788439644911793978499419995990477371552926308078495",
        System.Globalization.CultureInfo.InvariantCulture);
    private const int GeneratorY = 19;
    private const int CurveMinusD = 39081;

    /// <summary>edwards_scale loops while j = p &gt;&gt; 1 is non-zero: once per bit of p &gt;&gt; 1, 447 times.</summary>
    internal const int LadderSteps = (Size * 8) - 1;

    /// <summary>The smallest non-square n ≥ 2 that spake2ee_h2P searches for; for this p it is 7.</summary>
    internal const int NonSquare = 7;

    /// <summary>spake2ee_h2P: the point for a 56-byte big-endian password hash, via Elligator 2.</summary>
    internal static Point HashToPoint(ReadOnlySpan<byte> hash)
        => Elligator2(Element.FromBigEndian(hash));

    /// <summary>A uniformly random scalar in [0, p), as mpnrand(p).</summary>
    internal static byte[] RandomScalar(SecureRandom random)
    {
        var bytes = new byte[Size];
        while (true)
        {
            random.NextBytes(bytes);
            if (new BigInteger(bytes, isUnsigned: true, isBigEndian: true) < P) return bytes;
        }
    }

    /// <summary>spake2ee_1: y = decaf_encode(x*G + P).</summary>
    internal static byte[] PublicValue(ReadOnlySpan<byte> scalar, Point blinding)
    {
        Element x = Element.FromBigInteger(GeneratorX);
        Element y = Element.FromInt(GeneratorY);
        var generator = new Point(x, y, Element.FromInt(1), x * y);
        return DecafEncode(Scale(scalar, generator) + blinding);
    }

    /// <summary>
    /// spake2ee_2: z = decaf_encode(x*(Y - P)), or null when Y is not a valid Decaf encoding.
    /// </summary>
    internal static byte[]? SharedValue(ReadOnlySpan<byte> scalar, ReadOnlySpan<byte> peer, Point blinding)
    {
        Point? decoded = DecafDecode(peer);
        if (decoded is null) return null;
        return DecafEncode(Scale(scalar, decoded.Value + blinding.Negate()));
    }

    /// <summary>edwards_scale: a fixed-length ladder over the bits of s, selecting in constant time.</summary>
    private static Point Scale(ReadOnlySpan<byte> scalar, Point point)
    {
        Point doubling = point;
        Point result = Point.Select(Bit(scalar, 0), point, Point.Identity());
        for (int index = 1; index <= LadderSteps; index++)
        {
            doubling += doubling;
            Point sum = doubling + result;
            result = Point.Select(Bit(scalar, index), sum, result);
        }

        return result;
    }

    /// <summary>Bit <paramref name="index"/> of a 56-byte big-endian scalar, as 0 or 1.</summary>
    private static int Bit(ReadOnlySpan<byte> bigEndian, int index)
        => (bigEndian[bigEndian.Length - 1 - (index / 8)] & (1 << (index % 8))) != 0 ? 1 : 0;

    /// <summary>elligator2.mp with a = 1.</summary>
    private static Point Elligator2(Element r0)
    {
        Element one = Element.FromInt(1);
        Element d = -Element.FromInt(CurveMinusD);
        Element n = Element.FromInt(NonSquare);
        Element aMinus2d = one - (d + d);
        Element r = n * r0 * r0;
        Element denominator = (d * r + one - d) * (d * r - r - d);
        Element numerator = (r + one) * aMinus2d;
        Element nd = numerator * denominator;

        Element c;
        Element e;
        if (nd.IsZero)
        {
            c = one;
            e = Element.FromInt(0);
        }
        else
        {
            e = Msqrt(nd);
            if (!e.IsZero)
            {
                c = one;
                e = e.Invert();
            }
            else
            {
                c = -one;
                e = n * r0 * Misqrt(n * nd);
            }
        }

        Element s = c * numerator * e;
        Element t = -(c * numerator * (r - one) * (aMinus2d * e).Square()) - one;
        Element ss = s * s;
        return new Point((s + s) * t, (one - ss) * (one + ss), (one + ss) * t, (s + s) * (one - ss));
    }

    /// <summary>decaf.mp decaf_encode with a = 1.</summary>
    private static byte[] DecafEncode(Point point)
    {
        Element one = Element.FromInt(1);
        Element d = -Element.FromInt(CurveMinusD);
        Element aMinusD = one - d;
        Element r = Misqrt(aMinusD * (point.Z + point.Y) * (point.Z - point.Y));
        Element u = aMinusD * r;
        Element twoUZ = u * point.Z;
        r = NegateIfHigh(-(twoUZ + twoUZ), r);
        Element s = u * (r * (point.Z * point.X - d * point.Y * point.T) + point.Y);
        return NegateIfHigh(s, s).ToBigEndian();
    }

    /// <summary>decaf.mp decaf_decode with a = 1; null when ok would be 0.</summary>
    private static Point? DecafDecode(ReadOnlySpan<byte> encoded)
    {
        BigInteger value = new(encoded, isUnsigned: true, isBigEndian: true);
        if (value > HalfP) return null;
        Element one = Element.FromInt(1);
        Element d = -Element.FromInt(CurveMinusD);
        Element s = Element.FromBigInteger(value);
        Element ss = s.Square();
        Element z = one + ss;
        Element u = z.Square() - Element.FromInt(4) * d * ss;
        Element v = u * ss;
        if (!v.IsZero)
        {
            Element root = Msqrt(v);
            if (root.IsZero) return null;
            v = root.Invert();
        }

        v = NegateIfHigh(u * v, v);
        Element w = v * s * (Element.FromInt(2) - z);
        // w is 0 when s is; 9front adds 1 to it.
        if (s.IsZero) w = one;
        Element x = s + s;
        return new Point(x, w * z, z, w * x);
    }

    /// <summary>decaf_neg: -r when n &gt; (p-1)/2, else r.</summary>
    internal static Element NegateIfHigh(Element n, Element r) => n.ToBigInteger() > HalfP ? -r : r;

    /// <summary>msqrt for p ≡ 3 (mod 4): a^((p+1)/4) when a is a non-zero square, else 0.</summary>
    private static Element Msqrt(Element a)
        => Legendre(a) == 1 ? a.Pow((P + 1) / 4) : Element.FromInt(0);

    /// <summary>misqrt for p ≡ 3 (mod 4): a^((p-3)/4).</summary>
    private static Element Misqrt(Element a) => a.Pow((P - 3) / 4);

    /// <summary>legendresymbol: a^((p-1)/2), mapped to -1, 0 or 1.</summary>
    internal static int Legendre(Element a)
    {
        BigInteger r = a.Pow((P - 1) / 2).ToBigInteger();
        return r == P - 1 ? -1 : (int)r;
    }

    /// <summary>An element of GF(p) on X448Field limbs.</summary>
    internal readonly struct Element
    {
        private readonly uint[] limbs;

        private Element(uint[] limbs) => this.limbs = limbs;

        internal bool IsZero => ToBigInteger().IsZero;

        /// <summary>X448Field.Add does not carry; carrying keeps limbs within Mul's input bounds.</summary>
        public static Element operator +(Element left, Element right)
        {
            Element sum = Apply(left, right, X448Field.Add);
            X448Field.Carry(sum.limbs);
            return sum;
        }

        public static Element operator -(Element left, Element right) => Apply(left, right, X448Field.Sub);

        public static Element operator *(Element left, Element right) => Apply(left, right, X448Field.Mul);

        public static Element operator -(Element value)
        {
            uint[] result = X448Field.Create();
            X448Field.Negate(value.limbs, result);
            return new Element(result);
        }

        /// <summary>A small non-negative constant; negative constants are written as -FromInt(n).</summary>
        internal static Element FromInt(int value) => FromBigInteger(value);

        internal static Element FromBigInteger(BigInteger value)
        {
            var bytes = new byte[Size];
            value.TryWriteBytes(bytes, out _, isUnsigned: true, isBigEndian: false);
            uint[] limbs = X448Field.Create();
            X448Field.Decode448(bytes, limbs);
            return new Element(limbs);
        }

        /// <summary>Reads a 56-byte big-endian value. Values at or above p reduce, as h%p does, because the field is mod p.</summary>
        internal static Element FromBigEndian(ReadOnlySpan<byte> bigEndian)
            => FromBigInteger(new BigInteger(bigEndian, isUnsigned: true, isBigEndian: true));

        internal Element Square()
        {
            uint[] result = X448Field.Create();
            X448Field.Sqr(limbs, result);
            return new Element(result);
        }

        internal Element Invert()
        {
            uint[] result = X448Field.Create();
            X448Field.Inv(limbs, result);
            return new Element(result);
        }

        /// <summary>Square-and-multiply over the bits of a public exponent, most significant first.</summary>
        internal Element Pow(BigInteger exponent)
        {
            byte[] bits = exponent.ToByteArray();
            Element result = FromInt(1);
            foreach (int bit in Enumerable.Range(0, (int)exponent.GetBitLength()).Reverse())
            {
                result = result.Square();
                if ((bits[bit / 8] & (1 << (bit % 8))) != 0) result *= this;
            }

            return result;
        }

        internal BigInteger ToBigInteger()
        {
            uint[] copy = Copy();
            X448Field.Normalize(copy);
            var bytes = new byte[Size];
            X448Field.Encode(copy, bytes, 0);
            return new BigInteger(bytes, isUnsigned: true, isBigEndian: false);
        }

        internal byte[] ToBigEndian()
        {
            BigInteger value = ToBigInteger();
            var bytes = new byte[Size];
            int length = value.GetByteCount(isUnsigned: true);
            value.TryWriteBytes(bytes.AsSpan(Size - length), out _, isUnsigned: true, isBigEndian: true);
            return bytes;
        }

        /// <summary>Constant-time selection; condition is 0 or 1. X448Field.CMov takes a mask, so 1 becomes -1.</summary>
        internal static Element Select(int condition, Element whenSet, Element whenClear)
        {
            uint[] result = whenClear.Copy();
            X448Field.CMov(-condition, whenSet.limbs, 0, result, 0);
            return new Element(result);
        }

        private uint[] Copy()
        {
            uint[] copy = X448Field.Create();
            X448Field.Copy(limbs, 0, copy, 0);
            return copy;
        }

        private static Element Apply(Element left, Element right, Action<uint[], uint[], uint[]> operation)
        {
            uint[] result = X448Field.Create();
            operation(left.limbs, right.limbs, result);
            return new Element(result);
        }
    }

    /// <summary>A point in extended coordinates (X, Y, Z, T), T = XY/Z.</summary>
    internal readonly record struct Point(Element X, Element Y, Element Z, Element T)
    {
        internal static Point Identity() => new(Element.FromInt(0), Element.FromInt(1), Element.FromInt(1), Element.FromInt(0));

        /// <summary>The 224-byte encoding authpak_hash stores: X, Y, Z, T, each 56 bytes big-endian.</summary>
        internal byte[] ToBigEndian() => [.. X.ToBigEndian(), .. Y.ToBigEndian(), .. Z.ToBigEndian(), .. T.ToBigEndian()];

        internal static Point FromBigEndian(ReadOnlySpan<byte> encoded)
            => new(Element.FromBigEndian(encoded[..Size]), Element.FromBigEndian(encoded.Slice(Size, Size)),
                Element.FromBigEndian(encoded.Slice(2 * Size, Size)), Element.FromBigEndian(encoded.Slice(3 * Size, Size)));

        /// <summary>-P = (-X, Y, Z, -T), as spake2ee_2 passes it.</summary>
        internal Point Negate() => new(-X, Y, Z, -T);

        /// <summary>edwards_add with a = 1.</summary>
        public static Point operator +(Point left, Point right)
        {
            Element d = -Element.FromInt(CurveMinusD);
            Element a = left.X * right.X;
            Element b = left.Y * right.Y;
            Element c = d * left.T * right.T;
            Element dz = left.Z * right.Z;
            Element e = (left.X + left.Y) * (right.X + right.Y) - a - b;
            Element f = dz - c;
            Element g = dz + c;
            Element h = b - a;
            return new Point(e * f, g * h, f * g, e * h);
        }

        internal static Point Select(int condition, Point whenSet, Point whenClear)
            => new(Element.Select(condition, whenSet.X, whenClear.X), Element.Select(condition, whenSet.Y, whenClear.Y),
                Element.Select(condition, whenSet.Z, whenClear.Z), Element.Select(condition, whenSet.T, whenClear.T));
    }
}
