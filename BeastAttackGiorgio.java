import java.io.*;
import java.nio.ByteBuffer;
import javax.xml.bind.annotation.adapters.HexBinaryAdapter;
import java.util.Arrays;

import java.util.ArrayList;
import java.util.Scanner;


public class BeastAttackGiorgio
{
    public static void main(String[] args) throws Exception
    {
        // Estimate the most frequent increment among 100 tried of the IV

        final int MAX_TRIES = 100;
        int[] occurrencies = new int[1000];

        byte[] ciphertext = new byte[1024]; 
        callEncrypt(null, 0, ciphertext);
        byte[] PreviousIV = Arrays.copyOfRange(ciphertext, 0, 8);

        int most_frequent     = 0;
        int guessed_increment = 0;
        for(int i = 0; i < MAX_TRIES; i++)
        {
            callEncrypt(null, 0, ciphertext);
            byte[] CurrentIV = Arrays.copyOfRange(ciphertext, 0, 8);
            
            long PreviousIVval = ByteBuffer.wrap(PreviousIV).getLong();
            long CurrentIVval = ByteBuffer.wrap(CurrentIV).getLong();

            // Compute difference between current IV and previous IV for each iteration
            int difference = (int)(CurrentIVval - PreviousIVval);
            occurrencies[difference]++;

            if(occurrencies[difference] > most_frequent)
            {
                most_frequent = occurrencies[difference];
                guessed_increment = difference;
            }

            // Update value of current IV
            PreviousIV = CurrentIV;

        }
        
        ArrayList<Byte> foundLetters = new ArrayList<Byte>();
        byte[] RealIV = PreviousIV;
        while(foundLetters.size() < 8)
        {
            for(int i = 0; i < MAX_TRIES; i++)
            {
                // Create a guessIV incrementing previousIV by the most frequent difference
                byte[] GuessIV = RealIV;
                long GuessIVval = ByteBuffer.wrap(GuessIV).getLong() + guessed_increment;
                GuessIV = ByteBuffer.allocate(Long.SIZE / Byte.SIZE).putLong(GuessIVval).array();

                // Generate new prefix by xoring 0s with guessIV
                byte[] prefix = generate_zeros_prefix(7 - foundLetters.size());
                byte[] xored_prefix = new byte[prefix.length];
                for(int j = 0; j < prefix.length; j++)
                {
                    xored_prefix[j] = (byte)(prefix[j] ^ GuessIV[j]);
                }

                // Encrypt the prefix and check whether the IV in the output is the same as GuessIV. Store c1,...,c8      
                callEncrypt(xored_prefix, xored_prefix.length, ciphertext);
                RealIV = Arrays.copyOfRange(ciphertext, 0, 8);
                byte[] iv1iv8 = RealIV;
                byte[] c1c8 = Arrays.copyOfRange(ciphertext, 8, 16);

                if(Arrays.equals(RealIV, GuessIV))
                {
                    boolean x_found = false;

                    // Try all possible values of x
                    for(byte x = 0; x < 256; x++)
                    {
                        // For each value of x, guess multiple IVs
                        for(int j = 0; j < MAX_TRIES; j++)
                        {
                            GuessIV = RealIV;
                            GuessIVval = ByteBuffer.wrap(GuessIV).getLong() + guessed_increment;
                            GuessIV = ByteBuffer.allocate(Long.SIZE / Byte.SIZE).putLong(GuessIVval).array();

                            // Create new prefix to guess the value of x
                            byte[] guess_prefix = generate_prefix(7 - foundLetters.size(), foundLetters, x);
                            byte[] xored_guess_prefix = new byte[8];
                            for(int k = 0; k < guess_prefix.length; k++)
                            {
                                xored_guess_prefix[k] = (byte)(guess_prefix[k] ^ GuessIV[k]);
                            }
                            for(int k = guess_prefix.length - foundLetters.size() - 1; k < guess_prefix.length - 1; k++)
                            {
                                xored_guess_prefix[k] = (byte)(xored_guess_prefix[k] ^ iv1iv8[k]);
                            }

                            // Call callEncrypt on the guessed prefix and store c1,...,c8
                            callEncrypt(xored_guess_prefix, xored_guess_prefix.length, ciphertext);
                            RealIV = Arrays.copyOfRange(ciphertext, 0, 8);
                            byte[] guess_c1c8 = Arrays.copyOfRange(ciphertext, 8, 16);

                            if(Arrays.equals(RealIV, GuessIV))
                            {
                                if(Arrays.equals(c1c8, guess_c1c8))
                                {
                                    byte match = (byte)(guess_prefix[7] ^ iv1iv8[7]);
                                    foundLetters.add(match);

                                    for(byte b : foundLetters)
                                    {
                                        System.out.print((char)b);
                                    }
                                    System.out.println();

                                    x_found = true;
                                }
                                break;
                            }
                        }
                        if(x_found)
                        {
                            break;
                        }
                    }
                    break;
                }
            }
        }
    }
    
    // Method to generate the prefix for our guess of the cipher block: uses number of zeros, the letters found so far, and the variable x
	public static byte[] generate_prefix(int zeros, ArrayList<Byte> foundLetters, byte x) throws Exception
    {
        byte[] prefix = new byte[8];
        for(int i = 0; i < zeros; i++)
        {
            prefix[i] = 0;
        }
        for(int i = zeros; i < 7; i++)
        {
            prefix[i] = foundLetters.get(i - zeros);
        }

        prefix[7] = x;

        return prefix;
    }

    // Method to generate prefix constiting of only 0s to create the target cipher block
    public static byte[] generate_zeros_prefix(int zeros) throws Exception
    {
        byte[] zeros_prefix = new byte[zeros];
        for(int i = 0; i < zeros; i++)
        {
            zeros_prefix[i] = 0;
        }
        return zeros_prefix;
    }

    // a helper method to call the external programme "encrypt" in the current directory
    // the parameters are the plaintext, length of plaintext, and ciphertext; returns length of ciphertext
    static int callEncrypt(byte[] prefix, int prefix_len, byte[] ciphertext) throws IOException
    {
        HexBinaryAdapter adapter = new HexBinaryAdapter();
        Process process;
        
        // run the external process (don't bother to catch exceptions)
        if(prefix != null)
        {
            // turn prefix byte array into hex string
            byte[] p=Arrays.copyOfRange(prefix, 0, prefix_len);
            String PString=adapter.marshal(p);
            process = Runtime.getRuntime().exec("./encrypt "+PString);
        }
        else
        {
            process = Runtime.getRuntime().exec("./encrypt");
        }

    // process the resulting hex string
        String CString = (new BufferedReader(new InputStreamReader(process.getInputStream()))).readLine();
        byte[] c=adapter.unmarshal(CString);
        System.arraycopy(c, 0, ciphertext, 0, c.length); 
        return(c.length);
    }
}

