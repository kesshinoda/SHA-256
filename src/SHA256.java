import java.math.BigInteger;
import java.util.Scanner;

/*
    This program is SHA 256.
    In this program, binary string is mainly used to process.
    When the input message is converted to a binary string, it is encoded by using UTF-8.
*/

class shaTwo
{
    private static String bitwiseAnd(String a, String b)
    {
        //This method takes two strings and use AND operator on them.
        String product = "";
        for (int i = 0; i < a.length(); i++)
        {
            if (a.charAt(i) == b.charAt(i) & a.charAt(i) == '1')
                product = product + "1";
            else
                product = product + "0";
        }
        return product;
    }

    private static String bitwiseXor(String a, String b)
    {
        //This method takes two strings and use XOR operator on them.
        String s = "";
        for (int i = 0; i < a.length(); i++)
            s = s + (a.charAt(i) ^ b.charAt(i));
        return s;
    }

    private static String bitwiseComp(String a)
    {
        //This method takes one string and use negation on them.
        String comp = "";
        for (int i = 0; i < a.length(); i++)
        {
            if (a.charAt(i) == '1')
                comp = comp + "0";
            else
                comp = comp + "1";
        }
        return comp;
    }

    private static String ch(String x, String y, String z)
    {
        //This is Ch function. Ch(x,y,z) = (x AND y) XOR ((NEGATE)x AND z)
        String xy = bitwiseAnd(x, y);
        String xz = bitwiseAnd(bitwiseComp(x),z);
        return bitwiseXor(xy, xz);
    }

    private static String maj(String x, String y, String z)
    {
        //This is Maj function. Maj(x,y,z) = (x AND y) XOR (x AND z) XOR (y AND z)
        String xy = bitwiseAnd(x, y);
        String xz = bitwiseAnd(x, z);
        String yz = bitwiseAnd(y, z);
        return bitwiseXor(bitwiseXor(xy, xz), yz);
    }

    public static String rightShift(String s, int n)
    {
        //This is also called SHR function.
        //Move each bit of position to the right by n times.
        //The most left bit will be O, and the most right bit will be eliminated.
        if(n == 0)
            return s;
        else
        {
            s = "0" + s.substring(0, s.length()-1);
            return rightShift(s, n-1);
        }
    }

    public static String rightCircularShift(String s, int n)
    {
        //This is also called ROTR function
        //Move each bit of position to the right and the most right digit will be added in the most left position.
        //This method do this operation for n times.
        if (n == 0)
            return s;
        else
        {
            char temp = s.charAt(s.length()-1);
            s = temp + s.substring(0, s.length()-1);
            return rightCircularShift(s, n - 1);
        }
    }

    private static String bigSigmaZero(String x)
    {
        //This is Big Sigma Zero function.
        //bigSigmaZero(x) = ROTR(x,2) XOR ROTR(x,13) XOR ROTR(x,22)
        return bitwiseXor(bitwiseXor(rightCircularShift(x,2),rightCircularShift(x,13)),rightCircularShift(x,22));
    }

    private static String bigSigmaOne(String x)
    {
        //This is Big Sigma One function.
        //bigSigmaOne(x) = ROTR(x,6) XOR ROTR(x,11) XOR ROTR(x,25)
        return bitwiseXor(bitwiseXor(rightCircularShift(x,6),rightCircularShift(x,11)),rightCircularShift(x,25));
    }

    private static String smallSigmaZero(String x)
    {
        //This is Small Sigma Zero function.
        //smallSigmaZero(x) = ROTR(x,7) XOR ROTR(x,18) XOR SHR(x,25)
        return bitwiseXor(bitwiseXor(rightCircularShift(x,7),rightCircularShift(x,18)),rightShift(x,3));
    }

    private static String smallSigmaOne(String x)
    {
        //This is Small Sigma One function.
        //smallSigmaOne(x) = ROTR(x,17) XOR ROTR(x,19) XOR SHR(x,10)
        return bitwiseXor(bitwiseXor(rightCircularShift(x,17),rightCircularShift(x,19)),rightShift(x,10));
    }

    private static String add(String x, String y)
    {
        //Convert two strings to two bigInteger base 2, bigX and bigY.
        //Reduce the addition of bigX and bigY by mod 2^32 = 4294967296.
        BigInteger bigX = new BigInteger(x,2);
        BigInteger bigY = new BigInteger(y,2);
        BigInteger m = new BigInteger("4294967296");
        BigInteger bigZ = new BigInteger(String.valueOf(bigX.add(bigY).mod(m)));
        return fillZeros(bigZ.toString(2),32);
    }

    private static String padding(String message)
    {
        //This method pads four binary strings together.
        //First, compute int k such that k = 448 - (l+1) (mod 512) where l is the length of the message
        //Second, pad message(binary string), "1", k zeros, and 64 bits string, which is l in base 2.
        //Thus, the padded length will be the multiple of 512.
        int k = (448 - (message.length() + 1)) % 512;
        if(k < 0) k += 512;
        String m = Integer.toString(message.length(), 2);
        return message + "1" + fillZeros(m, 64 + k);
    }


    private static String[] parseData(String message)
    {
        // This method breaks a message into 512 bit blocks.
        if (message.length() % 512 != 0)
            message = padding(message);
        int n = message.length() / 512;
        String[] dataArray = new String[n];
        for (int i = 0; i < message.length(); i += 512)
            dataArray[i / 512] = message.substring(i, i + 512);
        return dataArray;
    }

    private static String fillZeros(String b, int n)
    {
        //This method add zeros on the left side until the total length reach n
        while (b.length() < n)
            b = "0" + b;
        return b;
    }

    public static String hash(String message)
    {
        //This method takes a message and return its hash value.
        message = stringToBinary(message);
        String[] messageArray = parseData(message);

        String[] H = {"6a09e667","bb67ae85","3c6ef372","a54ff53a","510e527f","9b05688c","1f83d9ab","5be0cd19"};
        for(int i = 0; i < H.length; i++)
        {
            BigInteger Hi = new BigInteger(H[i], 16);
            H[i] = fillZeros(Hi.toString(2),32);
        }

        String[] K = {"428a2f98", "71374491", "b5c0fbcf", "e9b5dba5", "3956c25b", "59f111f1", "923f82a4", "ab1c5ed5",
                "d807aa98", "12835b01", "243185be", "550c7dc3", "72be5d74", "80deb1fe", "9bdc06a7", "c19bf174",
                "e49b69c1", "efbe4786", "0fc19dc6", "240ca1cc", "2de92c6f", "4a7484aa", "5cb0a9dc", "76f988da",
                "983e5152", "a831c66d", "b00327c8", "bf597fc7", "c6e00bf3", "d5a79147", "06ca6351", "14292967",
                "27b70a85", "2e1b2138", "4d2c6dfc", "53380d13", "650a7354", "766a0abb", "81c2c92e", "92722c85",
                "a2bfe8a1", "a81a664b", "c24b8b70", "c76c51a3", "d192e819", "d6990624", "f40e3585", "106aa070",
                "19a4c116", "1e376c08", "2748774c", "34b0bcb5", "391c0cb3", "4ed8aa4a", "5b9cca4f", "682e6ff3",
                "748f82ee", "78a5636f", "84c87814", "8cc70208", "90befffa", "a4506ceb", "bef9a3f7", "c67178f2"};
        for(int i = 0; i < K.length; i++)
        {
            BigInteger Ki = new BigInteger(K[i], 16);
            K[i] = fillZeros(Ki.toString(2),32);
        }

        for(int i = 0; i < messageArray.length; i++)
        {
            String[] W = new String[64];
            for(int t = 0; t < W.length; t++)
            {
                if(t < 16)
                    W[t] = messageArray[i].substring(t*32,(t+1)*32);
                else
                    W[t] = add(add(add(smallSigmaOne(W[t-2]),W[t-7]),smallSigmaZero(W[t-15])),W[t-16]);
            }

            String a = H[0];
            String b = H[1];
            String c = H[2];
            String d = H[3];
            String e = H[4];
            String f = H[5];
            String g = H[6];
            String h = H[7];

            for(int t = 0; t < W.length; t++)
            {
                String TOne = add(add(add(add(h,bigSigmaOne(e)),ch(e,f,g)),K[t]),W[t]) ;
                String TTwo = add(bigSigmaZero(a),maj(a,b,c));
                h = g;
                g = f;
                f = e;
                e = add(d,TOne);
                d = c;
                c = b;
                b = a;
                a = add(TOne,TTwo);
            }

            H[0] = add(a, H[0]);
            H[1] = add(b, H[1]);
            H[2] = add(c, H[2]);
            H[3] = add(d, H[3]);
            H[4] = add(e, H[4]);
            H[5] = add(f, H[5]);
            H[6] = add(g, H[6]);
            H[7] = add(h, H[7]);
        }
        return binaryToHex(H[0] + H[1] + H[2] + H[3] + H[4] + H[5] + H[6] + H[7]);
    }


    private static String stringToBinary(String m)
    {
        //This method converts given string to binary string by using UTF-8.
        String bin = "";
        for (int i = 0; i < m.length(); i++)
        {
            String temp = Integer.toBinaryString(m.charAt(i));
            while (temp.length() < 8)
                temp = "0" + temp;
            bin = bin + temp;
        }
        return bin;
    }

    private static String binaryToHex(String bin)
    {
        //This method converts given string to hex string.
        String hexString = "";
        for (int i = bin.length() - 1; i >= 0; i -= 4)
        {
            int n = Integer.parseInt(bin.substring(i - 3, i + 1), 2);
            hexString = Integer.toHexString(n) + hexString;
        }
        return hexString;
    }
}

public class SHA256
{
    public static void main(String[] args)
    {
        Scanner input = new Scanner(System.in);
        System.out.println("Enter message which length is less than 2^64");
        String message = input.nextLine();
        String hashed = shaTwo.hash(message);
        System.out.println(hashed);
    }
}