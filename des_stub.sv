/*
 Data Encryption Standard (S-DES)
 64-bit 16-round block cipher encryption and decryption algorithm 
 using 56-bit key (64-bit key with Parity).
 */

module GenerateKeys (Key, SubKey1, SubKey2, SubKey3, SubKey4,
		     SubKey5, SubKey6, SubKey7, SubKey8,
		     SubKey9, SubKey10, SubKey11, SubKey12,
		     SubKey13, SubKey14, SubKey15, SubKey16);
   
   // Generate SubKeys
   input logic [63:0]  Key;
   output logic [47:0] SubKey1;
   output logic [47:0] SubKey2;
   output logic [47:0] SubKey3;
   output logic [47:0] SubKey4;
   output logic [47:0] SubKey5;
   output logic [47:0] SubKey6;
   output logic [47:0] SubKey7;
   output logic [47:0] SubKey8;
   output logic [47:0] SubKey9;
   output logic [47:0] SubKey10;
   output logic [47:0] SubKey11;
   output logic [47:0] SubKey12;
   output logic [47:0] SubKey13;
   output logic [47:0] SubKey14;
   output logic [47:0] SubKey15;
   output logic [47:0] SubKey16;
   logic [55:0] TempKey1, TempKey2, TempKey3, TempKey4;
   logic [55:0] TempKey5, TempKey6, TempKey7, TempKey8;
   logic [55:0] TempKey9, TempKey10, TempKey11, TempKey12;
   logic [55:0] TempKey13, TempKey14, TempKey15, TempKey16;
   logic [27:0] pc1Key_left, pc1Key_right;
   
   PC1 KeyPC1(Key, pc1Key_left, pc1Key_right);
   
   assign TempKey1[55:28] = {pc1Key_left[26:0], pc1Key_left[27]};		//subkey1 generation @ 1 ROTATION
   assign TempKey1[27:0] = {pc1Key_right[26:0], pc1Key_right[27]};
   PC2 sk1(TempKey1[55:28], TempKey1[27:0], SubKey1);
    
   assign TempKey2[55:28] = {TempKey1[54:28], TempKey1[55]};			//subkey2 generation @ 1 ROTATION
   assign TempKey2[27:0]  = {TempKey1[26:0], TempKey1[27]};
   PC2 sk2(TempKey2[55:28], TempKey2[27:0], SubKey2);
   
   assign TempKey3[55:28] = {TempKey2[53:28], TempKey2[55:54]};			//subkey3 generation @ 2 ROTATIONS
   assign TempKey3[27:0]  = {TempKey2[25:0], TempKey2[27:26]};
   PC2 sk3(TempKey3[55:28], TempKey3[27:0], SubKey3);
   
   assign TempKey4[55:28] = {TempKey3[53:28], TempKey3[55:54]};				//subkey4 generation @ 2 ROTATION
   assign TempKey4[27:0]  = {TempKey3[25:0], TempKey3[27:26]};
   PC2 sk4(TempKey4[55:28], TempKey4[27:0], SubKey4);
   
   assign TempKey5[55:28] = {TempKey4[53:28], TempKey4[55:54]};			//subkey5 generation @ 2 ROTATIONS
   assign TempKey5[27:0]  = {TempKey4[25:0], TempKey4[27:26]};
   PC2 sk5(TempKey5[55:28], TempKey5[27:0], SubKey5);
   
   assign TempKey6[55:28] = {TempKey5[53:28], TempKey5[55:54]};			//subkey6 generation @ 2 ROTATIONS
   assign TempKey6[27:0]  = {TempKey5[25:0], TempKey5[27:26]};
   PC2 sk6(TempKey6[55:28], TempKey6[27:0], SubKey6);
   
   assign TempKey7[55:28] = {TempKey6[53:28], TempKey6[55:54]};			//subkey7 generation @ 2 ROTATIONS
   assign TempKey7[27:0]  = {TempKey6[25:0], TempKey6[27:26]};
   PC2 sk7(TempKey7[55:28], TempKey7[27:0], SubKey7);
   
   assign TempKey8[55:28] = {TempKey7[53:28], TempKey7[55:54]};			//subkey8 generation @ 2 ROTATIONS
   assign TempKey8[27:0]  = {TempKey7[25:0], TempKey7[27:26]};
   PC2 sk8(TempKey8[55:28], TempKey8[27:0], SubKey8);
   
   assign TempKey9[55:28] = {TempKey8[54:28], TempKey8[55]};				//subkey9 generation @ 1 ROTATION
   assign TempKey9[27:0]  = {TempKey8[26:0], TempKey8[27]};
   PC2 sk9(TempKey9[55:28], TempKey9[27:0], SubKey9);
   
   assign TempKey10[55:28] = {TempKey9[53:28], TempKey9[55:54]};			//subkey10 generation @ 2 ROTATIONS
   assign TempKey10[27:0]  = {TempKey9[25:0], TempKey9[27:26]};
   PC2 sk10(TempKey10[55:28], TempKey10[27:0], SubKey10);
   
   assign TempKey11[55:28] = {TempKey10[53:28], TempKey10[55:54]};			//subkey11 generation @ 2 ROTATIONS
   assign TempKey11[27:0]  = {TempKey10[25:0], TempKey10[27:26]};
   PC2 sk11(TempKey11[55:28], TempKey11[27:0], SubKey11);
   
   assign TempKey12[55:28] = {TempKey11[53:28], TempKey11[55:54]};			//subkey12 generation @ 2 ROTATIONS
   assign TempKey12[27:0]  = {TempKey11[25:0], TempKey11[27:26]};
   PC2 sk12(TempKey12[55:28], TempKey12[27:0], SubKey12);
   
   assign TempKey13[55:28] = {TempKey12[53:28], TempKey12[55:54]};			//subkey13 generation @ 2 ROTATIONS
   assign TempKey13[27:0]  = {TempKey12[25:0], TempKey12[27:26]};
   PC2 sk13(TempKey13[55:28], TempKey13[27:0], SubKey13);
   
   assign TempKey14[55:28] = {TempKey13[53:28], TempKey13[55:54]};			//subkey14 generation @ 2 ROTATIONS
   assign TempKey14[27:0]  = {TempKey13[25:0], TempKey13[27:26]};
   PC2 sk14(TempKey14[55:28], TempKey14[27:0], SubKey14);
   
   assign TempKey15[55:28] = {TempKey14[53:28], TempKey14[55:54]};			//subkey15 generation @ 2 ROTATIONS
   assign TempKey15[27:0]  = {TempKey14[25:0], TempKey14[27:26]};
   PC2 sk15(TempKey15[55:28], TempKey15[27:0], SubKey15);
   
   assign TempKey16[55:28] = {TempKey15[54:28], TempKey15[55]};				//subkey16 generation @ 1 ROTATION
   assign TempKey16[27:0]  = {TempKey15[26:0], TempKey15[27]};
   PC2 sk16(TempKey16[55:28], TempKey16[27:0], SubKey16);
   
endmodule // GenerateKeys

module PC1 (key, left_block, right_block);

   input logic [63:0]  key;
   output logic [27:0] left_block;
   output logic [27:0] right_block;
   
   assign left_block[27] = key[64-57];
   assign left_block[26] = key[64-49];
   assign left_block[25] = key[64-41];
   assign left_block[24] = key[64-33];
   assign left_block[23] = key[64-25];
   assign left_block[22] = key[64-17];
   assign left_block[21] = key[64-9];
   assign left_block[20] = key[64-1];
   assign left_block[19] = key[64-58];
   assign left_block[18] = key[64-50];
   assign left_block[17] = key[64-42];
   assign left_block[16] = key[64-34];
   assign left_block[15] = key[64-26];
   assign left_block[14] = key[64-18];
   assign left_block[13] = key[64-10];
   assign left_block[12] = key[64-2];
   assign left_block[11] = key[64-59];
   assign left_block[10] = key[64-51];
   assign left_block[9] = key[64-43];
   assign left_block[8] = key[64-35];
   assign left_block[7] = key[64-27];
   assign left_block[6] = key[64-19];
   assign left_block[5] = key[64-11];
   assign left_block[4] = key[64-3];
   assign left_block[3] = key[64-60];
   assign left_block[2] = key[64-52];
   assign left_block[1] = key[64-44];
   assign left_block[0] = key[64-36];
   
   assign right_block[27] = key[64-63];
   assign right_block[26] = key[64-55];
   assign right_block[25] = key[64-47];
   assign right_block[24] = key[64-39];
   assign right_block[23] = key[64-31];
   assign right_block[22] = key[64-23];
   assign right_block[21] = key[64-15];
   assign right_block[20] = key[64-7];
   assign right_block[19] = key[64-62];
   assign right_block[18] = key[64-54];
   assign right_block[17] = key[64-46];
   assign right_block[16] = key[64-38];
   assign right_block[15] = key[64-30];
   assign right_block[14] = key[64-22];
   assign right_block[13] = key[64-14];
   assign right_block[12] = key[64-6];
   assign right_block[11] = key[64-61];
   assign right_block[10] = key[64-53];
   assign right_block[9] = key[64-45];
   assign right_block[8] = key[64-37];
   assign right_block[7] = key[64-29];
   assign right_block[6] = key[64-21];
   assign right_block[5] = key[64-13];
   assign right_block[4] = key[64-5];
   assign right_block[3] = key[64-28];
   assign right_block[2] = key[64-20];
   assign right_block[1] = key[64-12];
   assign right_block[0] = key[64-4];

endmodule // PC1

module PC2 (left_block, right_block, subkey);

   input logic [27:0] left_block;
   input logic [27:0] right_block;
   output logic [47:0] subkey;
   logic [55:0] TempKey;
   assign TempKey[55:0] = {left_block[27:0], right_block[27:0]};
   
   assign subkey[47] = TempKey[56-14];
   assign subkey[46] = TempKey[56-17];
   assign subkey[45] = TempKey[56-11];
   assign subkey[44] = TempKey[56-24];
   assign subkey[43] = TempKey[56-1];
   assign subkey[42] = TempKey[56-5];
   assign subkey[41] = TempKey[56-3];
   assign subkey[40] = TempKey[56-28];
   assign subkey[39] = TempKey[56-15];
   assign subkey[38] = TempKey[56-6];
   assign subkey[37] = TempKey[56-21];
   assign subkey[36] = TempKey[56-10];
   assign subkey[35] = TempKey[56-23];
   assign subkey[34] = TempKey[56-19];
   assign subkey[33] = TempKey[56-12];
   assign subkey[32] = TempKey[56-4];
   assign subkey[31] = TempKey[56-26];
   assign subkey[30] = TempKey[56-8];
   assign subkey[29] = TempKey[56-16];
   assign subkey[28] = TempKey[56-7];
   assign subkey[27] = TempKey[56-27];
   assign subkey[26] = TempKey[56-20];
   assign subkey[25] = TempKey[56-13];
   assign subkey[24] = TempKey[56-2];
   assign subkey[23] = TempKey[56-41];
   assign subkey[22] = TempKey[56-52];
   assign subkey[21] = TempKey[56-31];
   assign subkey[20] = TempKey[56-37];
   assign subkey[19] = TempKey[56-47];
   assign subkey[18] = TempKey[56-55];
   assign subkey[17] = TempKey[56-30];
   assign subkey[16] = TempKey[56-40];
   assign subkey[15] = TempKey[56-51];
   assign subkey[14] = TempKey[56-45];
   assign subkey[13] = TempKey[56-33];
   assign subkey[12] = TempKey[56-48];
   assign subkey[11] = TempKey[56-44];
   assign subkey[10] = TempKey[56-49];
   assign subkey[9] = TempKey[56-39];
   assign subkey[8] = TempKey[56-56];
   assign subkey[7] = TempKey[56-34];
   assign subkey[6] = TempKey[56-53];
   assign subkey[5] = TempKey[56-46];
   assign subkey[4] = TempKey[56-42];
   assign subkey[3] = TempKey[56-50];
   assign subkey[2] = TempKey[56-36];
   assign subkey[1] = TempKey[56-29];
   assign subkey[0] = TempKey[56-32];

endmodule // PC2

// Straight Function
module SF (inp_block, out_block);

   input logic [31:0] inp_block;
   output logic [31:0] out_block;
   
   assign out_block[31] = inp_block[32-16];
   assign out_block[30] = inp_block[32-7];
   assign out_block[29] = inp_block[32-20];
   assign out_block[28] = inp_block[32-21];
   assign out_block[27] = inp_block[32-29];
   assign out_block[26] = inp_block[32-12];
   assign out_block[25] = inp_block[32-28];
   assign out_block[24] = inp_block[32-17];
   assign out_block[23] = inp_block[32-1];
   assign out_block[22] = inp_block[32-15];
   assign out_block[21] = inp_block[32-23];
   assign out_block[20] = inp_block[32-26];
   assign out_block[19] = inp_block[32-5];
   assign out_block[18] = inp_block[32-18];
   assign out_block[17] = inp_block[32-31];
   assign out_block[16] = inp_block[32-10];
   assign out_block[15] = inp_block[32-2];
   assign out_block[14] = inp_block[32-8];
   assign out_block[13] = inp_block[32-24];
   assign out_block[12] = inp_block[32-14];
   assign out_block[11] = inp_block[32-32];
   assign out_block[10] = inp_block[32-27];
   assign out_block[9] = inp_block[32-3];
   assign out_block[8] = inp_block[32-9];
   assign out_block[7] = inp_block[32-19];
   assign out_block[6] = inp_block[32-13];
   assign out_block[5] = inp_block[32-30];
   assign out_block[4] = inp_block[32-6];
   assign out_block[3] = inp_block[32-22];
   assign out_block[2] = inp_block[32-11];
   assign out_block[1] = inp_block[32-4];
   assign out_block[0] = inp_block[32-25];

endmodule // SF

// Expansion Function
module EF (inp_block, out_block);

	input logic [31:0] inp_block;
	output logic [47:0] out_block;
	   
	   assign out_block[47] = inp_block[32-32];
	   assign out_block[46] = inp_block[32-1];
	   assign out_block[45] = inp_block[32-2];
	   assign out_block[44] = inp_block[32-3];
	   assign out_block[43] = inp_block[32-4];
	   assign out_block[42] = inp_block[32-5];
	   assign out_block[41] = inp_block[32-4];
	   assign out_block[40] = inp_block[32-5];
	   assign out_block[39] = inp_block[32-6];
	   assign out_block[38] = inp_block[32-7];
	   assign out_block[37] = inp_block[32-8];
	   assign out_block[36] = inp_block[32-9];
	   assign out_block[35] = inp_block[32-8];
	   assign out_block[34] = inp_block[32-9];
	   assign out_block[33] = inp_block[32-10];
	   assign out_block[32] = inp_block[32-11];
	   assign out_block[31] = inp_block[32-12];
	   assign out_block[30] = inp_block[32-13];
	   assign out_block[29] = inp_block[32-12];
	   assign out_block[28] = inp_block[32-13];
	   assign out_block[27] = inp_block[32-14];
	   assign out_block[26] = inp_block[32-15];
	   assign out_block[25] = inp_block[32-16];
	   assign out_block[24] = inp_block[32-17];
	   assign out_block[23] = inp_block[32-16];
	   assign out_block[22] = inp_block[32-17];
	   assign out_block[21] = inp_block[32-18];
	   assign out_block[20] = inp_block[32-19];
	   assign out_block[19] = inp_block[32-20];
	   assign out_block[18] = inp_block[32-21];
	   assign out_block[17] = inp_block[32-20];
	   assign out_block[16] = inp_block[32-21];
	   assign out_block[15] = inp_block[32-22];
	   assign out_block[14] = inp_block[32-23];
	   assign out_block[13] = inp_block[32-24];
	   assign out_block[12] = inp_block[32-25];
	   assign out_block[11] = inp_block[32-24];
	   assign out_block[10] = inp_block[32-25];
	   assign out_block[9] = inp_block[32-26];
	   assign out_block[8] = inp_block[32-27];
	   assign out_block[7] = inp_block[32-28];
	   assign out_block[6] = inp_block[32-29];
	   assign out_block[5] = inp_block[32-28];
	   assign out_block[4] = inp_block[32-29];
	   assign out_block[3] = inp_block[32-30];
	   assign out_block[2] = inp_block[32-31];
	   assign out_block[1] = inp_block[32-32];
	   assign out_block[0] = inp_block[32-1];

endmodule // EF

module feistel (inp_block, subkey, out_block);

   input logic [31:0]  inp_block;
   input logic [47:0]  subkey;
   output logic [31:0] out_block;
   logic [47:0] expand_out;
   logic [47:0] s_in;
   logic [31:0] s_out;
   
   EF exp (inp_block[31:0], expand_out);
   
   assign s_in[47:0] = expand_out[47:0] ^ subkey[47:0];
   
   S1_Box s1(s_in[47:42], s_out[31:28]);
   S2_Box s2(s_in[41:36], s_out[27:24]);
   S3_Box s3(s_in[35:30], s_out[23:20]);
   S4_Box s4(s_in[29:24], s_out[19:16]);
   S5_Box s5(s_in[23:18], s_out[15:12]);
   S6_Box s6(s_in[17:12], s_out[11:8]);
   S7_Box s7(s_in[11:6], s_out[7:4]);
   S8_Box s8(s_in[5:0], s_out[3:0]);
   
   SF SF(s_out, out_block);

endmodule // Feistel

// DES block round
module round (inp_block, subkey, out_block);

   input logic [63:0]  inp_block;
   input logic [47:0]  subkey;
   output logic [63:0] out_block;
   logic [31:0] feistel_out;
   
   assign out_block[63:32] = inp_block[31:0];		//L[i] = R[i-1] 
   feistel f1 (inp_block[31:0], subkey[47:0], feistel_out[31:0]);		

   assign out_block[31:0] = feistel_out[31:0] ^ inp_block[63:32];  //R[i] = L[i-1] + feistel(R[i-1])

endmodule // round1

// Initial Permutation
module IP (inp_block, out_block);

   input logic [63:0]  inp_block;
   output logic [63:0] out_block;

   assign out_block[63] = inp_block[64-58];
   assign out_block[62] = inp_block[64-50];
   assign out_block[61] = inp_block[64-42];
   assign out_block[60] = inp_block[64-34];
   assign out_block[59] = inp_block[64-26];
   assign out_block[58] = inp_block[64-18];
   assign out_block[57] = inp_block[64-10];
   assign out_block[56] = inp_block[64-2];
   assign out_block[55] = inp_block[64-60];
   assign out_block[54] = inp_block[64-52];   
   assign out_block[53] = inp_block[64-44];   
   assign out_block[52] = inp_block[64-36];
   assign out_block[51] = inp_block[64-28];
   assign out_block[50] = inp_block[64-20];
   assign out_block[49] = inp_block[64-12];
   assign out_block[48] = inp_block[64-4];
   assign out_block[47] = inp_block[64-62];
   assign out_block[46] = inp_block[64-54];
   assign out_block[45] = inp_block[64-46];
   assign out_block[44] = inp_block[64-38];   
   assign out_block[43] = inp_block[64-30];
   assign out_block[42] = inp_block[64-22];   
   assign out_block[41] = inp_block[64-14];
   assign out_block[40] = inp_block[64-6];
   assign out_block[39] = inp_block[64-64];
   assign out_block[38] = inp_block[64-56];
   assign out_block[37] = inp_block[64-48];
   assign out_block[36] = inp_block[64-40];
   assign out_block[35] = inp_block[64-32];
   assign out_block[34] = inp_block[64-24];   
   assign out_block[33] = inp_block[64-16];
   assign out_block[32] = inp_block[64-8];   
   assign out_block[31] = inp_block[64-57];
   assign out_block[30] = inp_block[64-49];
   assign out_block[29] = inp_block[64-41];
   assign out_block[28] = inp_block[64-33];
   assign out_block[27] = inp_block[64-25];
   assign out_block[26] = inp_block[64-17];
   assign out_block[25] = inp_block[64-9];   
   assign out_block[24] = inp_block[64-1];   
   assign out_block[23] = inp_block[64-59];
   assign out_block[22] = inp_block[64-51];   
   assign out_block[21] = inp_block[64-43];
   assign out_block[20] = inp_block[64-35];
   assign out_block[19] = inp_block[64-27];
   assign out_block[18] = inp_block[64-19];
   assign out_block[17] = inp_block[64-11];
   assign out_block[16] = inp_block[64-3];
   assign out_block[15] = inp_block[64-61];
   assign out_block[14] = inp_block[64-53];   
   assign out_block[13] = inp_block[64-45];
   assign out_block[12] = inp_block[64-37];   
   assign out_block[11] = inp_block[64-29];
   assign out_block[10] = inp_block[64-21];
   assign out_block[9] = inp_block[64-13];
   assign out_block[8] = inp_block[64-5];
   assign out_block[7] = inp_block[64-63];
   assign out_block[6] = inp_block[64-55];
   assign out_block[5] = inp_block[64-47];
   assign out_block[4] = inp_block[64-39];   
   assign out_block[3] = inp_block[64-31];
   assign out_block[2] = inp_block[64-23];    
   assign out_block[1] = inp_block[64-15];
   assign out_block[0] = inp_block[64-7];   

endmodule // IP

// Final Permutation
module FP (inp_block, out_block);

   input logic [63:0]  inp_block;
   output logic [63:0] out_block;

   assign out_block[63] = inp_block[64-40];
   assign out_block[62] = inp_block[64-8];
   assign out_block[61] = inp_block[64-48];
   assign out_block[60] = inp_block[64-16];
   assign out_block[59] = inp_block[64-56];
   assign out_block[58] = inp_block[64-24];
   assign out_block[57] = inp_block[64-64];
   assign out_block[56] = inp_block[64-32];   
   assign out_block[55] = inp_block[64-39];
   assign out_block[54] = inp_block[64-7];   
   assign out_block[53] = inp_block[64-47];   
   assign out_block[52] = inp_block[64-15];
   assign out_block[51] = inp_block[64-55];
   assign out_block[50] = inp_block[64-23];
   assign out_block[49] = inp_block[64-63];
   assign out_block[48] = inp_block[64-31];   
   assign out_block[47] = inp_block[64-38];
   assign out_block[46] = inp_block[64-6];
   assign out_block[45] = inp_block[64-46];
   assign out_block[44] = inp_block[64-14];   
   assign out_block[43] = inp_block[64-54];
   assign out_block[42] = inp_block[64-22];   
   assign out_block[41] = inp_block[64-62];
   assign out_block[40] = inp_block[64-30];   
   assign out_block[39] = inp_block[64-37];
   assign out_block[38] = inp_block[64-5];
   assign out_block[37] = inp_block[64-45];
   assign out_block[36] = inp_block[64-13];
   assign out_block[35] = inp_block[64-53];
   assign out_block[34] = inp_block[64-21];   
   assign out_block[33] = inp_block[64-61];
   assign out_block[32] = inp_block[64-29];   
   assign out_block[31] = inp_block[64-36];
   assign out_block[30] = inp_block[64-4];
   assign out_block[29] = inp_block[64-44];
   assign out_block[28] = inp_block[64-12];
   assign out_block[27] = inp_block[64-52];
   assign out_block[26] = inp_block[64-20];
   assign out_block[25] = inp_block[64-60];   
   assign out_block[24] = inp_block[64-28];   
   assign out_block[23] = inp_block[64-35];
   assign out_block[22] = inp_block[64-3];   
   assign out_block[21] = inp_block[64-43];
   assign out_block[20] = inp_block[64-11];
   assign out_block[19] = inp_block[64-51];
   assign out_block[18] = inp_block[64-19];
   assign out_block[17] = inp_block[64-59];
   assign out_block[16] = inp_block[64-27];   
   assign out_block[15] = inp_block[64-34];
   assign out_block[14] = inp_block[64-2];   
   assign out_block[13] = inp_block[64-42];
   assign out_block[12] = inp_block[64-10];   
   assign out_block[11] = inp_block[64-50];
   assign out_block[10] = inp_block[64-18];
   assign out_block[9] = inp_block[64-58];
   assign out_block[8] = inp_block[64-26];   
   assign out_block[7] = inp_block[64-33];
   assign out_block[6] = inp_block[64-1];
   assign out_block[5] = inp_block[64-41];   
   assign out_block[4] = inp_block[64-9];
   assign out_block[3] = inp_block[64-49];    
   assign out_block[2] = inp_block[64-17];
   assign out_block[1] = inp_block[64-57];
   assign out_block[0] = inp_block[64-25];  

endmodule // FP

module S1_Box (inp_bits, out_bits);

   input logic [5:0] inp_bits;
   output logic [3:0] out_bits;

   always_comb
     begin
	case ({{inp_bits[5], inp_bits[0]}, inp_bits[4:1]})
	  6'd0  : out_bits = 4'd14;             
	  6'd1  : out_bits = 4'd4;             
	  6'd2  : out_bits = 4'd13;            
	  6'd3  : out_bits = 4'd1;             
	  6'd4  : out_bits = 4'd2;             
	  6'd5  : out_bits = 4'd15;             
	  6'd6  : out_bits = 4'd11;             
	  6'd7  : out_bits = 4'd8;             
	  6'd8  : out_bits = 4'd3;             
	  6'd9  : out_bits = 4'd10;             
	  6'd10 : out_bits = 4'd6;             
	  6'd11 : out_bits = 4'd12;             
	  6'd12 : out_bits = 4'd5;             
	  6'd13 : out_bits = 4'd9;             
	  6'd14 : out_bits = 4'd0;             
	  6'd15 : out_bits = 4'd7;             
	  6'd16 : out_bits = 4'd0;             
	  6'd17 : out_bits = 4'd15;             
	  6'd18 : out_bits = 4'd7;             
	  6'd19 : out_bits = 4'd4;             
	  6'd20 : out_bits = 4'd14;             
	  6'd21 : out_bits = 4'd2;             
	  6'd22 : out_bits = 4'd13;             
	  6'd23 : out_bits = 4'd1;             
	  6'd24 : out_bits = 4'd10;             
	  6'd25 : out_bits = 4'd6;             
	  6'd26 : out_bits = 4'd12;             
	  6'd27 : out_bits = 4'd11;             
	  6'd28 : out_bits = 4'd9;             
	  6'd29 : out_bits = 4'd5;             
	  6'd30 : out_bits = 4'd3;             
	  6'd31 : out_bits = 4'd8;             
	  6'd32 : out_bits = 4'd4;             
	  6'd33 : out_bits = 4'd1;             
	  6'd34 : out_bits = 4'd14;             
	  6'd35 : out_bits = 4'd8;             
	  6'd36 : out_bits = 4'd13;             
	  6'd37 : out_bits = 4'd6;             
	  6'd38 : out_bits = 4'd2;             
	  6'd39 : out_bits = 4'd11;             
	  6'd40 : out_bits = 4'd15;             
	  6'd41 : out_bits = 4'd12;             
	  6'd42 : out_bits = 4'd9;             
	  6'd43 : out_bits = 4'd7;             
	  6'd44 : out_bits = 4'd3;             
	  6'd45 : out_bits = 4'd10;             
	  6'd46 : out_bits = 4'd5;             
	  6'd47 : out_bits = 4'd0;             
	  6'd48 : out_bits = 4'd15;             
	  6'd49 : out_bits = 4'd12;             
	  6'd50 : out_bits = 4'd8;             
	  6'd51 : out_bits = 4'd2;             
	  6'd52 : out_bits = 4'd4;             
	  6'd53 : out_bits = 4'd9;            
	  6'd54 : out_bits = 4'd1;             
	  6'd55 : out_bits = 4'd7;            
	  6'd56 : out_bits = 4'd5;        
	  6'd57 : out_bits = 4'd11;        
	  6'd58 : out_bits = 4'd3;       
	  6'd59 : out_bits = 4'd14;       
	  6'd60 : out_bits = 4'd10;       
	  6'd61 : out_bits = 4'd0;       
	  6'd62 : out_bits = 4'd6;      
	  6'd63 : out_bits = 4'd13;      
	  default : out_bits = 4'd0; 		
        endcase
     end // always_comb
   
endmodule // S1_Box

module S2_Box (inp_bits, out_bits);

   input logic [5:0] inp_bits;
   output logic [3:0] out_bits;

   always_comb
     begin
	case ({{inp_bits[5], inp_bits[0]}, inp_bits[4:1]})             
	  6'd0  : out_bits = 4'd15;             
	  6'd1  : out_bits = 4'd1;             
	  6'd2  : out_bits = 4'd8;            
	  6'd3  : out_bits = 4'd14;             
	  6'd4  : out_bits = 4'd6;             
	  6'd5  : out_bits = 4'd11;             
	  6'd6  : out_bits = 4'd3;             
	  6'd7  : out_bits = 4'd4;             
	  6'd8  : out_bits = 4'd9;             
	  6'd9  : out_bits = 4'd7;             
	  6'd10 : out_bits = 4'd2;             
	  6'd11 : out_bits = 4'd13;             
	  6'd12 : out_bits = 4'd12;             
	  6'd13 : out_bits = 4'd0;             
	  6'd14 : out_bits = 4'd5;             
	  6'd15 : out_bits = 4'd10;             
	  6'd16 : out_bits = 4'd3;             
	  6'd17 : out_bits = 4'd13;             
	  6'd18 : out_bits = 4'd4;             
	  6'd19 : out_bits = 4'd7;             
	  6'd20 : out_bits = 4'd15;             
	  6'd21 : out_bits = 4'd2;             
	  6'd22 : out_bits = 4'd8;             
	  6'd23 : out_bits = 4'd14;             
	  6'd24 : out_bits = 4'd12;             
	  6'd25 : out_bits = 4'd0;             
	  6'd26 : out_bits = 4'd1;             
	  6'd27 : out_bits = 4'd10;             
	  6'd28 : out_bits = 4'd6;             
	  6'd29 : out_bits = 4'd9;             
	  6'd30 : out_bits = 4'd11;             
	  6'd31 : out_bits = 4'd5;             
	  6'd32 : out_bits = 4'd0;             
	  6'd33 : out_bits = 4'd14;             
	  6'd34 : out_bits = 4'd7;             
	  6'd35 : out_bits = 4'd11;             
	  6'd36 : out_bits = 4'd10;             
	  6'd37 : out_bits = 4'd4;             
	  6'd38 : out_bits = 4'd13;             
	  6'd39 : out_bits = 4'd1;             
	  6'd40 : out_bits = 4'd5;             
	  6'd41 : out_bits = 4'd8;             
	  6'd42 : out_bits = 4'd12;             
	  6'd43 : out_bits = 4'd6;             
	  6'd44 : out_bits = 4'd9;             
	  6'd45 : out_bits = 4'd3;             
	  6'd46 : out_bits = 4'd2;             
	  6'd47 : out_bits = 4'd15;             
	  6'd48 : out_bits = 4'd13;             
	  6'd49 : out_bits = 4'd8;             
	  6'd50 : out_bits = 4'd10;             
	  6'd51 : out_bits = 4'd1;             
	  6'd52 : out_bits = 4'd3;             
	  6'd53 : out_bits = 4'd15;            
	  6'd54 : out_bits = 4'd4;             
	  6'd55 : out_bits = 4'd2;            
	  6'd56 : out_bits = 4'd11;        
	  6'd57 : out_bits = 4'd6;        
	  6'd58 : out_bits = 4'd7;       
	  6'd59 : out_bits = 4'd12;       
	  6'd60 : out_bits = 4'd0;       
	  6'd61 : out_bits = 4'd5;       
	  6'd62 : out_bits = 4'd14;      
	  6'd63 : out_bits = 4'd9;      
	  default : out_bits = 4'd0; 		
        endcase
     end // always_comb
   
endmodule // S2_Box

module S3_Box (inp_bits, out_bits);

   input logic [5:0] inp_bits;
   output logic [3:0] out_bits;

   always_comb
     begin
	case ({{inp_bits[5], inp_bits[0]}, inp_bits[4:1]})
	  6'd0  : out_bits = 4'd10;             
	  6'd1  : out_bits = 4'd0;             
	  6'd2  : out_bits = 4'd9;            
	  6'd3  : out_bits = 4'd14;             
	  6'd4  : out_bits = 4'd6;             
	  6'd5  : out_bits = 4'd3;             
	  6'd6  : out_bits = 4'd15;             
	  6'd7  : out_bits = 4'd5;             
	  6'd8  : out_bits = 4'd1;             
	  6'd9  : out_bits = 4'd13;             
	  6'd10 : out_bits = 4'd12;             
	  6'd11 : out_bits = 4'd7;             
	  6'd12 : out_bits = 4'd11;             
	  6'd13 : out_bits = 4'd4;             
	  6'd14 : out_bits = 4'd2;             
	  6'd15 : out_bits = 4'd8;             
	  6'd16 : out_bits = 4'd13;             
	  6'd17 : out_bits = 4'd7;             
	  6'd18 : out_bits = 4'd0;             
	  6'd19 : out_bits = 4'd9;             
	  6'd20 : out_bits = 4'd3;             
	  6'd21 : out_bits = 4'd4;             
	  6'd22 : out_bits = 4'd6;             
	  6'd23 : out_bits = 4'd10;             
	  6'd24 : out_bits = 4'd2;             
	  6'd25 : out_bits = 4'd8;             
	  6'd26 : out_bits = 4'd5;             
	  6'd27 : out_bits = 4'd14;             
	  6'd28 : out_bits = 4'd12;             
	  6'd29 : out_bits = 4'd11;             
	  6'd30 : out_bits = 4'd15;             
	  6'd31 : out_bits = 4'd1;             
	  6'd32 : out_bits = 4'd13;             
	  6'd33 : out_bits = 4'd6;             
	  6'd34 : out_bits = 4'd4;             
	  6'd35 : out_bits = 4'd9;             
	  6'd36 : out_bits = 4'd8;             
	  6'd37 : out_bits = 4'd15;             
	  6'd38 : out_bits = 4'd3;             
	  6'd39 : out_bits = 4'd0;             
	  6'd40 : out_bits = 4'd11;             
	  6'd41 : out_bits = 4'd1;             
	  6'd42 : out_bits = 4'd2;             
	  6'd43 : out_bits = 4'd12;             
	  6'd44 : out_bits = 4'd5;             
	  6'd45 : out_bits = 4'd10;             
	  6'd46 : out_bits = 4'd14;             
	  6'd47 : out_bits = 4'd7;             
	  6'd48 : out_bits = 4'd1;             
	  6'd49 : out_bits = 4'd10;             
	  6'd50 : out_bits = 4'd13;             
	  6'd51 : out_bits = 4'd0;             
	  6'd52 : out_bits = 4'd6;             
	  6'd53 : out_bits = 4'd9;            
	  6'd54 : out_bits = 4'd8;             
	  6'd55 : out_bits = 4'd7;            
	  6'd56 : out_bits = 4'd4;        
	  6'd57 : out_bits = 4'd15;        
	  6'd58 : out_bits = 4'd14;       
	  6'd59 : out_bits = 4'd3;       
	  6'd60 : out_bits = 4'd11;       
	  6'd61 : out_bits = 4'd5;       
	  6'd62 : out_bits = 4'd2;      
	  6'd63 : out_bits = 4'd12;      
	  default : out_bits = 4'd0; 		
        endcase
     end // always_comb
   
endmodule // S3_Box

module S4_Box (inp_bits, out_bits);

   input logic [5:0] inp_bits;
   output logic [3:0] out_bits;

   always_comb
     begin
	case ({{inp_bits[5], inp_bits[0]}, inp_bits[4:1]})   
	  6'd0  : out_bits = 4'd7;             
	  6'd1  : out_bits = 4'd13;             
	  6'd2  : out_bits = 4'd14;            
	  6'd3  : out_bits = 4'd3;             
	  6'd4  : out_bits = 4'd0;             
	  6'd5  : out_bits = 4'd6;             
	  6'd6  : out_bits = 4'd9;             
	  6'd7  : out_bits = 4'd10;             
	  6'd8  : out_bits = 4'd1;             
	  6'd9  : out_bits = 4'd2;             
	  6'd10 : out_bits = 4'd8;             
	  6'd11 : out_bits = 4'd5;             
	  6'd12 : out_bits = 4'd11;             
	  6'd13 : out_bits = 4'd12;             
	  6'd14 : out_bits = 4'd4;             
	  6'd15 : out_bits = 4'd15;             
	  6'd16 : out_bits = 4'd13;             
	  6'd17 : out_bits = 4'd8;             
	  6'd18 : out_bits = 4'd11;             
	  6'd19 : out_bits = 4'd5;             
	  6'd20 : out_bits = 4'd6;             
	  6'd21 : out_bits = 4'd15;             
	  6'd22 : out_bits = 4'd0;             
	  6'd23 : out_bits = 4'd3;             
	  6'd24 : out_bits = 4'd4;             
	  6'd25 : out_bits = 4'd7;             
	  6'd26 : out_bits = 4'd2;             
	  6'd27 : out_bits = 4'd12;             
	  6'd28 : out_bits = 4'd1;             
	  6'd29 : out_bits = 4'd10;             
	  6'd30 : out_bits = 4'd14;             
	  6'd31 : out_bits = 4'd9;             
	  6'd32 : out_bits = 4'd10;             
	  6'd33 : out_bits = 4'd6;             
	  6'd34 : out_bits = 4'd9;             
	  6'd35 : out_bits = 4'd0;             
	  6'd36 : out_bits = 4'd12;             
	  6'd37 : out_bits = 4'd11;             
	  6'd38 : out_bits = 4'd7;             
	  6'd39 : out_bits = 4'd13;             
	  6'd40 : out_bits = 4'd15;             
	  6'd41 : out_bits = 4'd1;             
	  6'd42 : out_bits = 4'd3;             
	  6'd43 : out_bits = 4'd14;             
	  6'd44 : out_bits = 4'd5;             
	  6'd45 : out_bits = 4'd2;             
	  6'd46 : out_bits = 4'd8;             
	  6'd47 : out_bits = 4'd4;             
	  6'd48 : out_bits = 4'd3;             
	  6'd49 : out_bits = 4'd15;             
	  6'd50 : out_bits = 4'd0;             
	  6'd51 : out_bits = 4'd6;             
	  6'd52 : out_bits = 4'd10;             
	  6'd53 : out_bits = 4'd1;            
	  6'd54 : out_bits = 4'd13;             
	  6'd55 : out_bits = 4'd8;            
	  6'd56 : out_bits = 4'd9;        
	  6'd57 : out_bits = 4'd4;        
	  6'd58 : out_bits = 4'd5;       
	  6'd59 : out_bits = 4'd11;       
	  6'd60 : out_bits = 4'd12;       
	  6'd61 : out_bits = 4'd7;       
	  6'd62 : out_bits = 4'd2;      
	  6'd63 : out_bits = 4'd14;      
	  default : out_bits = 4'd0; 		
        endcase
     end // always_comb
   
endmodule // S4_Box

module S5_Box (inp_bits, out_bits);

   input logic [5:0] inp_bits;
   output logic [3:0] out_bits;

   always_comb
     begin
	case ({{inp_bits[5], inp_bits[0]}, inp_bits[4:1]})   
	  6'd0  : out_bits = 4'd2;             
	  6'd1  : out_bits = 4'd12;             
	  6'd2  : out_bits = 4'd4;            
	  6'd3  : out_bits = 4'd1;             
	  6'd4  : out_bits = 4'd7;             
	  6'd5  : out_bits = 4'd10;             
	  6'd6  : out_bits = 4'd11;             
	  6'd7  : out_bits = 4'd6;             
	  6'd8  : out_bits = 4'd8;             
	  6'd9  : out_bits = 4'd5;             
	  6'd10 : out_bits = 4'd3;             
	  6'd11 : out_bits = 4'd15;             
	  6'd12 : out_bits = 4'd13;             
	  6'd13 : out_bits = 4'd0;             
	  6'd14 : out_bits = 4'd14;             
	  6'd15 : out_bits = 4'd9;             
	  6'd16 : out_bits = 4'd14;             
	  6'd17 : out_bits = 4'd11;             
	  6'd18 : out_bits = 4'd2;             
	  6'd19 : out_bits = 4'd12;             
	  6'd20 : out_bits = 4'd4;             
	  6'd21 : out_bits = 4'd7;             
	  6'd22 : out_bits = 4'd13;             
	  6'd23 : out_bits = 4'd1;             
	  6'd24 : out_bits = 4'd5;             
	  6'd25 : out_bits = 4'd0;             
	  6'd26 : out_bits = 4'd15;             
	  6'd27 : out_bits = 4'd10;             
	  6'd28 : out_bits = 4'd3;             
	  6'd29 : out_bits = 4'd9;             
	  6'd30 : out_bits = 4'd8;             
	  6'd31 : out_bits = 4'd6;             
	  6'd32 : out_bits = 4'd4;             
	  6'd33 : out_bits = 4'd2;             
	  6'd34 : out_bits = 4'd1;             
	  6'd35 : out_bits = 4'd11;             
	  6'd36 : out_bits = 4'd10;             
	  6'd37 : out_bits = 4'd13;             
	  6'd38 : out_bits = 4'd7;             
	  6'd39 : out_bits = 4'd8;             
	  6'd40 : out_bits = 4'd15;             
	  6'd41 : out_bits = 4'd9;             
	  6'd42 : out_bits = 4'd12;             
	  6'd43 : out_bits = 4'd5;             
	  6'd44 : out_bits = 4'd6;             
	  6'd45 : out_bits = 4'd3;             
	  6'd46 : out_bits = 4'd0;             
	  6'd47 : out_bits = 4'd14;             
	  6'd48 : out_bits = 4'd11;             
	  6'd49 : out_bits = 4'd8;             
	  6'd50 : out_bits = 4'd12;             
	  6'd51 : out_bits = 4'd7;             
	  6'd52 : out_bits = 4'd1;             
	  6'd53 : out_bits = 4'd14;            
	  6'd54 : out_bits = 4'd2;             
	  6'd55 : out_bits = 4'd13;            
	  6'd56 : out_bits = 4'd6;        
	  6'd57 : out_bits = 4'd15;        
	  6'd58 : out_bits = 4'd0;       
	  6'd59 : out_bits = 4'd9;       
	  6'd60 : out_bits = 4'd10;       
	  6'd61 : out_bits = 4'd4;       
	  6'd62 : out_bits = 4'd5;      
	  6'd63 : out_bits = 4'd3;      
	  default : out_bits = 4'd0; 		
        endcase
     end // always_comb
   
endmodule // S5_Box

module S6_Box (inp_bits, out_bits);

   input logic [5:0] inp_bits;
   output logic [3:0] out_bits;

   always_comb
     begin
	case ({{inp_bits[5], inp_bits[0]}, inp_bits[4:1]})   
	  6'd0  : out_bits = 4'd12;             
	  6'd1  : out_bits = 4'd1;             
	  6'd2  : out_bits = 4'd10;            
	  6'd3  : out_bits = 4'd15;             
	  6'd4  : out_bits = 4'd9;             
	  6'd5  : out_bits = 4'd2;             
	  6'd6  : out_bits = 4'd6;             
	  6'd7  : out_bits = 4'd8;             
	  6'd8  : out_bits = 4'd0;             
	  6'd9  : out_bits = 4'd13;             
	  6'd10 : out_bits = 4'd3;             
	  6'd11 : out_bits = 4'd4;             
	  6'd12 : out_bits = 4'd14;             
	  6'd13 : out_bits = 4'd7;             
	  6'd14 : out_bits = 4'd5;             
	  6'd15 : out_bits = 4'd11;             
	  6'd16 : out_bits = 4'd10;             
	  6'd17 : out_bits = 4'd15;             
	  6'd18 : out_bits = 4'd4;             
	  6'd19 : out_bits = 4'd2;             
	  6'd20 : out_bits = 4'd7;             
	  6'd21 : out_bits = 4'd12;             
	  6'd22 : out_bits = 4'd9;             
	  6'd23 : out_bits = 4'd5;             
	  6'd24 : out_bits = 4'd6;             
	  6'd25 : out_bits = 4'd1;             
	  6'd26 : out_bits = 4'd13;             
	  6'd27 : out_bits = 4'd14;             
	  6'd28 : out_bits = 4'd0;             
	  6'd29 : out_bits = 4'd11;             
	  6'd30 : out_bits = 4'd3;             
	  6'd31 : out_bits = 4'd8;             
	  6'd32 : out_bits = 4'd9;             
	  6'd33 : out_bits = 4'd14;             
	  6'd34 : out_bits = 4'd15;             
	  6'd35 : out_bits = 4'd5;             
	  6'd36 : out_bits = 4'd2;             
	  6'd37 : out_bits = 4'd8;             
	  6'd38 : out_bits = 4'd12;             
	  6'd39 : out_bits = 4'd3;             
	  6'd40 : out_bits = 4'd7;             
	  6'd41 : out_bits = 4'd0;             
	  6'd42 : out_bits = 4'd4;             
	  6'd43 : out_bits = 4'd10;             
	  6'd44 : out_bits = 4'd1;             
	  6'd45 : out_bits = 4'd13;             
	  6'd46 : out_bits = 4'd11;             
	  6'd47 : out_bits = 4'd6;             
	  6'd48 : out_bits = 4'd4;             
	  6'd49 : out_bits = 4'd3;             
	  6'd50 : out_bits = 4'd2;             
	  6'd51 : out_bits = 4'd12;             
	  6'd52 : out_bits = 4'd9;             
	  6'd53 : out_bits = 4'd5;            
	  6'd54 : out_bits = 4'd15;             
	  6'd55 : out_bits = 4'd10;            
	  6'd56 : out_bits = 4'd11;        
	  6'd57 : out_bits = 4'd14;        
	  6'd58 : out_bits = 4'd1;       
	  6'd59 : out_bits = 4'd7;       
	  6'd60 : out_bits = 4'd6;       
	  6'd61 : out_bits = 4'd0;       
	  6'd62 : out_bits = 4'd8;      
	  6'd63 : out_bits = 4'd13;	  
	  default : out_bits = 4'd0; 		
        endcase
     end // always_comb
   
endmodule // S6_Box

module S7_Box (inp_bits, out_bits);

   input logic [5:0] inp_bits;
   output logic [3:0] out_bits;

   always_comb
     begin
	case ({{inp_bits[5], inp_bits[0]}, inp_bits[4:1]})   
	  6'd0  : out_bits = 4'd4;             
	  6'd1  : out_bits = 4'd11;             
	  6'd2  : out_bits = 4'd2;            
	  6'd3  : out_bits = 4'd14;             
	  6'd4  : out_bits = 4'd15;             
	  6'd5  : out_bits = 4'd0;             
	  6'd6  : out_bits = 4'd8;             
	  6'd7  : out_bits = 4'd13;             
	  6'd8  : out_bits = 4'd3;             
	  6'd9  : out_bits = 4'd12;             
	  6'd10 : out_bits = 4'd9;             
	  6'd11 : out_bits = 4'd7;             
	  6'd12 : out_bits = 4'd5;             
	  6'd13 : out_bits = 4'd10;             
	  6'd14 : out_bits = 4'd6;             
	  6'd15 : out_bits = 4'd1;             
	  6'd16 : out_bits = 4'd13;             
	  6'd17 : out_bits = 4'd0;             
	  6'd18 : out_bits = 4'd11;             
	  6'd19 : out_bits = 4'd7;             
	  6'd20 : out_bits = 4'd4;             
	  6'd21 : out_bits = 4'd9;             
	  6'd22 : out_bits = 4'd1;             
	  6'd23 : out_bits = 4'd10;             
	  6'd24 : out_bits = 4'd14;             
	  6'd25 : out_bits = 4'd3;             
	  6'd26 : out_bits = 4'd5;             
	  6'd27 : out_bits = 4'd12;             
	  6'd28 : out_bits = 4'd2;             
	  6'd29 : out_bits = 4'd15;             
	  6'd30 : out_bits = 4'd8;             
	  6'd31 : out_bits = 4'd6;             
	  6'd32 : out_bits = 4'd1;             
	  6'd33 : out_bits = 4'd4;             
	  6'd34 : out_bits = 4'd11;             
	  6'd35 : out_bits = 4'd13;             
	  6'd36 : out_bits = 4'd12;             
	  6'd37 : out_bits = 4'd3;             
	  6'd38 : out_bits = 4'd7;             
	  6'd39 : out_bits = 4'd14;             
	  6'd40 : out_bits = 4'd10;             
	  6'd41 : out_bits = 4'd15;             
	  6'd42 : out_bits = 4'd6;             
	  6'd43 : out_bits = 4'd8;             
	  6'd44 : out_bits = 4'd0;             
	  6'd45 : out_bits = 4'd5;             
	  6'd46 : out_bits = 4'd9;             
	  6'd47 : out_bits = 4'd2;             
	  6'd48 : out_bits = 4'd6;             
	  6'd49 : out_bits = 4'd11;             
	  6'd50 : out_bits = 4'd13;             
	  6'd51 : out_bits = 4'd8;             
	  6'd52 : out_bits = 4'd1;             
	  6'd53 : out_bits = 4'd4;            
	  6'd54 : out_bits = 4'd10;             
	  6'd55 : out_bits = 4'd7;            
	  6'd56 : out_bits = 4'd9;        
	  6'd57 : out_bits = 4'd5;        
	  6'd58 : out_bits = 4'd0;       
	  6'd59 : out_bits = 4'd15;       
	  6'd60 : out_bits = 4'd14;       
	  6'd61 : out_bits = 4'd2;       
	  6'd62 : out_bits = 4'd3;      
	  6'd63 : out_bits = 4'd12;  
	  default : out_bits = 4'd0; 		
        endcase
     end // always_comb
   
endmodule // S7_Box

module S8_Box (inp_bits, out_bits);

   input logic [5:0] inp_bits;
   output logic [3:0] out_bits;

   always_comb
     begin
	case ({{inp_bits[5], inp_bits[0]}, inp_bits[4:1]})   
	  6'd0  : out_bits = 4'd13;             
	  6'd1  : out_bits = 4'd2;             
	  6'd2  : out_bits = 4'd8;            
	  6'd3  : out_bits = 4'd4;             
	  6'd4  : out_bits = 4'd6;             
	  6'd5  : out_bits = 4'd15;             
	  6'd6  : out_bits = 4'd11;             
	  6'd7  : out_bits = 4'd1;             
	  6'd8  : out_bits = 4'd10;             
	  6'd9  : out_bits = 4'd9;             
	  6'd10 : out_bits = 4'd3;             
	  6'd11 : out_bits = 4'd14;             
	  6'd12 : out_bits = 4'd5;             
	  6'd13 : out_bits = 4'd0;             
	  6'd14 : out_bits = 4'd12;             
	  6'd15 : out_bits = 4'd7;             
	  6'd16 : out_bits = 4'd1;             
	  6'd17 : out_bits = 4'd15;             
	  6'd18 : out_bits = 4'd13;             
	  6'd19 : out_bits = 4'd8;             
	  6'd20 : out_bits = 4'd10;             
	  6'd21 : out_bits = 4'd3;             
	  6'd22 : out_bits = 4'd7;             
	  6'd23 : out_bits = 4'd4;             
	  6'd24 : out_bits = 4'd12;             
	  6'd25 : out_bits = 4'd5;             
	  6'd26 : out_bits = 4'd6;             
	  6'd27 : out_bits = 4'd11;             
	  6'd28 : out_bits = 4'd0;             
	  6'd29 : out_bits = 4'd14;             
	  6'd30 : out_bits = 4'd9;             
	  6'd31 : out_bits = 4'd2;             
	  6'd32 : out_bits = 4'd7;             
	  6'd33 : out_bits = 4'd11;             
	  6'd34 : out_bits = 4'd4;             
	  6'd35 : out_bits = 4'd1;             
	  6'd36 : out_bits = 4'd9;             
	  6'd37 : out_bits = 4'd12;             
	  6'd38 : out_bits = 4'd14;             
	  6'd39 : out_bits = 4'd2;             
	  6'd40 : out_bits = 4'd0;             
	  6'd41 : out_bits = 4'd6;             
	  6'd42 : out_bits = 4'd10;             
	  6'd43 : out_bits = 4'd13;             
	  6'd44 : out_bits = 4'd15;             
	  6'd45 : out_bits = 4'd3;             
	  6'd46 : out_bits = 4'd5;             
	  6'd47 : out_bits = 4'd8;             
	  6'd48 : out_bits = 4'd2;             
	  6'd49 : out_bits = 4'd1;             
	  6'd50 : out_bits = 4'd14;             
	  6'd51 : out_bits = 4'd7;             
	  6'd52 : out_bits = 4'd4;             
	  6'd53 : out_bits = 4'd10;            
	  6'd54 : out_bits = 4'd8;             
	  6'd55 : out_bits = 4'd13;            
	  6'd56 : out_bits = 4'd15;        
	  6'd57 : out_bits = 4'd12;        
	  6'd58 : out_bits = 4'd9;       
	  6'd59 : out_bits = 4'd0;       
	  6'd60 : out_bits = 4'd3;       
	  6'd61 : out_bits = 4'd5;       
	  6'd62 : out_bits = 4'd6;      
	  6'd63 : out_bits = 4'd11;      
	  default : out_bits = 4'd0; 		
        endcase
     end // always_comb
   
endmodule // S8_Box

module DES (input logic [63:0] key, input logic [63:0] plaintext, 
	    input logic encrypt, output logic [63:0] ciphertext);

   logic [47:0] 	SubKey1, SubKey2, SubKey3, SubKey4;   
   logic [47:0] 	SubKey5, SubKey6, SubKey7, SubKey8;   
   logic [47:0] 	SubKey9, SubKey10, SubKey11, SubKey12;
   logic [47:0] 	SubKey13, SubKey14, SubKey15, SubKey16;
   logic [47:0] 	SubKeyM1, SubKeyM2, SubKeyM3, SubKeyM4;   
   logic [47:0] 	SubKeyM5, SubKeyM6, SubKeyM7, SubKeyM8;   
   logic [47:0] 	SubKeyM9, SubKeyM10, SubKeyM11, SubKeyM12;
   logic [47:0] 	SubKeyM13, SubKeyM14, SubKeyM15, SubKeyM16;
   logic [63:0] 	ip_out;
   logic [63:0]		r1_out, r2_out, r3_out, r4_out;
   logic [63:0]		r5_out, r6_out, r7_out, r8_out;
   logic [63:0]		r9_out, r10_out, r11_out, r12_out;
   logic [63:0]		r13_out, r14_out, r15_out, r16_out;
   
   // SubKey generation
   GenerateKeys k1 (key, SubKey1, SubKey2, SubKey3, SubKey4,
		    SubKey5, SubKey6, SubKey7, SubKey8,
		    SubKey9, SubKey10, SubKey11, SubKey12,
		    SubKey13, SubKey14, SubKey15, SubKey16);
   // encrypt (encrypt=1) or decrypt (encrypt=0) 
   assign SubKeyM1 = encrypt ? SubKey1 : SubKey16;
   assign SubKeyM2 = encrypt ? SubKey2 : SubKey15;
   assign SubKeyM3 = encrypt ? SubKey3 : SubKey14;
   assign SubKeyM4 = encrypt ? SubKey4 : SubKey13;
   assign SubKeyM5 = encrypt ? SubKey5 : SubKey12;
   assign SubKeyM6 = encrypt ? SubKey6 : SubKey11;
   assign SubKeyM7 = encrypt ? SubKey7 : SubKey10;
   assign SubKeyM8 = encrypt ? SubKey8 : SubKey9;
   assign SubKeyM9 = encrypt ? SubKey9 : SubKey8;
   assign SubKeyM10 = encrypt ? SubKey10 : SubKey7;
   assign SubKeyM11 = encrypt ? SubKey11 : SubKey6;
   assign SubKeyM12 = encrypt ? SubKey12 : SubKey5;
   assign SubKeyM13 = encrypt ? SubKey13 : SubKey4;
   assign SubKeyM14 = encrypt ? SubKey14 : SubKey3;
   assign SubKeyM15 = encrypt ? SubKey15 : SubKey2;
   assign SubKeyM16 = encrypt ? SubKey16 : SubKey1;
   
	// Initial Permutation (IP)
	IP b1 (plaintext, ip_out);
	// round 1
	round r1 (ip_out, SubKeyM1, r1_out);
	// round 2
	round r2 (r1_out, SubKeyM2, r2_out);
	// round 3
	round r3 (r2_out, SubKeyM3, r3_out);
	// round 4
	round r4 (r3_out, SubKeyM4, r4_out);
	// round 5
	round r5 (r4_out, SubKeyM5, r5_out);
	// round 6
	round r6 (r5_out, SubKeyM6, r6_out);
	// round 7
	round r7 (r6_out, SubKeyM7, r7_out);
	// round 8
	round r8 (r7_out, SubKeyM8, r8_out);
	// round 9
	round r9 (r8_out, SubKeyM9, r9_out);
	// round 10
	round r10 (r9_out, SubKeyM10, r10_out);
	// round 11
	round r11 (r10_out, SubKeyM11, r11_out);
	// round 12
	round r12 (r11_out, SubKeyM12, r12_out);
	// round 13
	round r13 (r12_out, SubKeyM13, r13_out);
	// round 14
	round r14 (r13_out, SubKeyM14, r14_out);
	// round 15
	round r15 (r14_out, SubKeyM15, r15_out);
	// round 16
	round r16 (r15_out, SubKeyM16, r16_out);
	// Final Permutation (IP^{-1}) (swap output of round16)
	FP FP({r16_out[31:0], r16_out[63:32]}, ciphertext);
      
endmodule // DES


