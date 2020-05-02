import java.io.*;
import java.nio.ByteBuffer;

class DES{
    protected final static long MASK_6_BITS     = 0xFC0000000000L;
    protected final static long MASK_32_BITS    = 0xFFFFFFFFL;
    protected final static int  MASK_28_BITS    = 0x0FFFFFFF;
	protected final static int  NUM_OF_ROUNDS   = 16;
    private final static byte[] IP ={
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9,  1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    }; //Initial Permutation (IP) step.
    private final static byte[] FP =
    {
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25
    }; //Final Permutation (FP) step.

    private final RoundKeyGenerator keygen;
    private final FeistelFunction feistel;

    public DES(){
    	keygen = new RoundKeyGenerator();
    	feistel = new FeistelFunction();
    }
    //Wrapper for CBCMode(), specifying encryption.
    public long[] CBCEncrypt(long plainTexts[], long key, long IV){
    	return CBCMode(plainTexts, key, IV, true);
    }
    public long[] CBCDecrypt(long cipherTexts[], long key, long IV){
    	return CBCMode(cipherTexts, key, IV, false);
    }
    //Wrapper for cipher(), specifying encryption.
    public long encrypt(long block, long key){
    	return cipher(block, key, true);
    }
    public long decrypt(long block, long key){
    	return cipher(block, key, false);
    }
    /**
     * 64 bit blocks in @param input using @param key, @param encrypt -- encrypt or decrypt
     * @return array of 64 bit blocks---ciphered through DES CBC mode
     */
    private long[] CBCMode(long[] inputs, long key, long IV, boolean encrypt){
    	long[] outputs = new long[inputs.length];

    	long xor_val = IV;
    	for (int i = 0; i < inputs.length; i++)
    		if (encrypt){
    			outputs[i] = encrypt(inputs[i] ^ xor_val, key);
    			xor_val = outputs[i];
    		} else{
    			outputs[i] = decrypt(inputs[i], key) ^ xor_val;
    			xor_val = inputs[i];
    		}
    	return outputs;
    }
    /**
     * Main part of the DES algorithm
     * 64 bit @param block, generate round keys from @param key
     * @return 64 bit block of primitive type long
     */
    private long cipher(long block, long key, boolean encrypt){
    	long[] roundKeys = keygen.generateRoundKeys(key);
    	block = initialPermutation(block);
    	int leftHalf = (int) (block >> 32);		// get 32 MSBs
    	int rightHalf = (int) block;			// get 32 LSBs
    	int FOutput;
    	// 16 rounds of DES
    	for (int i = 0; i < DES.NUM_OF_ROUNDS; i++){
    		if (encrypt)
    			FOutput = feistel.F(rightHalf, roundKeys[i]);
    		else
    			FOutput = feistel.F(rightHalf, roundKeys[(DES.NUM_OF_ROUNDS-1)-i]);
    		// F function output XOR the left half
    		leftHalf ^= FOutput;
    		// XOR swapping algorithm left and right half 
    		leftHalf ^= rightHalf;
    		rightHalf ^= leftHalf;
    		leftHalf ^= rightHalf;
    	}
    	// reconstruct a 64 bit block
    	long joinedHalves = ((rightHalf & MASK_32_BITS) << 32 | (leftHalf & MASK_32_BITS));
    	return finalPermutation(joinedHalves);
    }    
    /** @return A 64 bit permutation of @param input according to table IP. */
    private long initialPermutation(long input){
    	return DES.genericPermutation(input, IP, 64);
    }
    /** @return A 64 bit permutation of @param input according to table FP. */
    private long finalPermutation(long input){
    	return DES.genericPermutation(input, FP, 64);
    }
    /** @return The 64 bit output containing the result of the permutation from the given table. */
    protected static long genericPermutation(long input, byte[] indexTable, int inputLength){
        long output = 0;
        int index;
        for (byte anIndexTable : indexTable) {
            index = inputLength - anIndexTable;
            output = (output << 1) | ((input >> index) & 1);
        }
        return output;
    }
}

class FeistelFunction{
    private static final byte[] E ={
        32, 1,  2,  3,  4,  5,
        4,  5,  6,  7,  8,  9,
        8,  9,  10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    }; // Expansion Permutation (E) step.
    private final static byte[][][] S_BOX =
    {{
    	{ 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
		{ 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
		{ 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
		{ 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 }
    },
    {
        { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
		{ 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
		{ 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
		{ 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 }
    },
    {
        { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
		{ 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
		{ 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
		{ 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 }
    },
    {
        { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
		{ 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
		{ 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
		{ 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 }
    },
    {
        { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
		{ 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
		{ 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
		{ 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 }
    },
    {
        { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
		{ 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
		{ 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
		{ 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 }
    },
    {
        { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
		{ 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
		{ 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
		{ 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 }
    },
    {
        { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
		{ 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
		{ 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
		{ 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
    }};  // 8 Substitution (S) box tables
    private final static byte[] P_BOX =
    {
        16, 7,  20, 21,
        29, 12, 28, 17,
        1,  15, 23, 26,
        5,  18, 31, 10,
        2,  8,  24, 14,
        32, 27, 3,  9,
        19, 13, 30, 6,
        22, 11, 4,  25
    }; // Permutation (P)-Box table
	/**
      @return 48 bits expanded from the 32 bit input
      Java longs are 64 bits, atleast 16 zero bits in the MSB positions
     */
    private long expansionPermutation(int input)
    {
        return DES.genericPermutation(input, E, 32);
    }
    /** 6 bit @param input, @return A byte containing the 4 bit value specified in the relevant S-box table */
    private byte SBoxSubstitution(int SBoxNum, byte input)
    {
    	byte row, col;
    	row = (byte) (((input & 0x20) >> 4) | input & 0x01);
    	col = (byte) ((input & 0x1E) >> 1);

        return S_BOX[SBoxNum][row][col];
    }
    /** 32 bit @param input, @return 32 bits of input permuted according to the P_BOX table indices. */
    private int PBoxPermutation(int input)
    {
        return (int) DES.genericPermutation(input, P_BOX, 32);
    }
    /** expansion permutation step @param input
     *  expanded @param input XOR @param roundKey
     *  @return The 32 bit output of the P-Box permutation step.
     */
    int F(int input, long roundKey){
        long output = expansionPermutation(input);
        output ^= roundKey;

        int SBoxOutputs = 0;
        for (int i = 0; i < 8; i++){
            SBoxOutputs <<= 4;
            SBoxOutputs |= SBoxSubstitution(i, (byte) ((output & DES.MASK_6_BITS) >> 42));
            output = output << 6;
        }

        return PBoxPermutation(SBoxOutputs);
    }
}

class RoundKeyGenerator{
    private final static byte[] PC1 ={
        57, 49, 41, 33, 25, 17, 9,
        1,  58, 50, 42, 34, 26, 18,
        10, 2,  59, 51, 43, 35, 27,
        19, 11, 3,  60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7,  62, 54, 46, 38, 30, 22,
        14, 6,  61, 53, 45, 37, 29,
        21, 13, 5,  28, 20, 12, 4
    }; // Permutation Choice 1 table
    private final static byte[] PC2={
        14, 17, 11, 24, 1,  5,
        3,  28, 15, 6,  21, 10,
        23, 19, 12, 4,  26, 8,
        16, 7,  27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    }; // Permutation Choice 2 table
    private final static byte[] CIRCULAR_SHIFTS ={
        1, 1, 2, 2,
        2, 2, 2, 2,
        1, 2, 2, 2,
        2, 2, 2, 1
    }; // number of left circular shifts

    /** @return 28 bit string---circular shifted left @param shift bits */
    private int circularLeftShift(int input, int shift){
    	return ((input << shift) & DES.MASK_28_BITS) | (input >> (28 - shift));
    }
    /** @param input 64 bit key @return 56 bit of 64 bits */
    private long permutationChoice1(long input){
    	return DES.genericPermutation(input, PC1, 64);
    }
    /** @param input 56 bit key @return 48 bit of 56 bits */
    private long permutationChoice2(long input){
    	return DES.genericPermutation(input, PC2, 56);
    }
    /** round keys from 64 bit @param input @return array of 16 longs representing 48 bit round keys */
    long[] generateRoundKeys(long input){
    	input = permutationChoice1(input);
    	int halfA = (int) (input >> 28);			// gets 28 MSBs
    	int halfB = (int) (input & DES.MASK_28_BITS);	// masks 28 LSBs
    	long[] roundKeys = new long[DES.NUM_OF_ROUNDS];
    	// generates all the 58 bit round keys for each round of DES and stores them in an array
    	for (int i = 0; i < DES.NUM_OF_ROUNDS; i++){
    		halfA = circularLeftShift(halfA, CIRCULAR_SHIFTS[i]);
    		halfB = circularLeftShift(halfB, CIRCULAR_SHIFTS[i]);

    		long joinedHalves = ((halfA & DES.MASK_32_BITS) << 28) | (halfB & DES.MASK_32_BITS);
    		roundKeys[i] = permutationChoice2(joinedHalves);
    	}
    	return roundKeys;
    }
}

class DESInterface{
    public static void main(String[] args){
        InputStreamReader is = new InputStreamReader(System.in);
        BufferedReader reader = new BufferedReader(is);

        System.out.println("Path to text file: ");
        byte[] text = getText(reader);
        System.out.println("64 bit key (as a string of text): ");
        long key = getKey(reader);
        System.out.println("64 bit initialisation vector (as string of text): ");
        long IV = getKey(reader);
        System.out.printf("Input plaintext: \n%s", new String(text));
        long[] blocks = splitInputIntoBlocks(text);
        runCBC(blocks, key, IV);
        try{
            reader.close();
        } 
        catch (IOException e){
            printErrorAndDie("Cannot close reader.");
        }
    }
    private static void runCBC(long[] blocks, long key, long IV){
        DES des = new DES();
        byte[] bytes;
        long[] cipherTexts, plainTexts;

        cipherTexts = des.CBCEncrypt(blocks, key, IV);

        System.out.println("\nEncrypted ciphertext: ");
        for (long block : cipherTexts){
            bytes = ByteBuffer.allocate(8).putLong(block).array();
            System.out.print(new String(bytes));
        }

        plainTexts = des.CBCDecrypt(cipherTexts, key, IV);
        System.out.println("\nDecrypted plaintext: ");
        for (long block : plainTexts){
            bytes = ByteBuffer.allocate(8).putLong(block).array();
            System.out.print(new String(bytes));
        }
    }

    private static long[] splitInputIntoBlocks(byte[] input){
        long blocks[] = new long[input.length / 8 + 1];
        for (int i = 0, j = -1; i < input.length; i++){
            if (i % 8 == 0)
                j++;
            blocks[j] <<= 8;
            blocks[j] |= input[i];
        }
        return blocks;
    }

    private static byte[] getText(BufferedReader reader){
        String path = "";
        try{
            path = reader.readLine();
        } 
        catch (IOException e){
            printErrorAndDie("");
        }

        return getByteArrayFromFile(path);
    }

    private static byte[] getByteArrayFromFile(String filePath){
        File file = new File(filePath);
        byte[] fileBuff = new byte[(int) file.length()];
        try{
            DataInputStream fileStream = new DataInputStream(new FileInputStream(file));
            fileStream.readFully(fileBuff);
            fileStream.close();
        } 
        catch (IOException e){
            printErrorAndDie("Cannot read from file.");
        }

        return fileBuff;
    }

    private static long getKey(BufferedReader reader){
        String keyStr = "";
        byte[] keyBytes;
        long key64 = 0;
        try{
            keyStr = reader.readLine();
        } 
        catch (IOException e){
            printErrorAndDie("");
        }
        if (keyStr.length() > 8){
            System.out.println("Input is greater than 64 bits.");
            System.exit(0);
        }

        keyBytes = keyStr.getBytes();

        for (byte keyByte : keyBytes){
            key64 <<= 8;
            key64 |= keyByte;
        }
        return key64;
    }
    
    private static void printErrorAndDie(String message){
        System.err.println("Fatal IO error encountered." + "\n" + message);
        System.exit(1);
    }
}