#ifndef __DEF_DES_H__
#define __DEF_DES_H__

#define uchar unsigned char
#define uint unsigned int

void three_des_crypt(uchar in[], uchar out[], uchar key[][16][6]);
void three_des_key_schedule(uchar key[], uchar schedule[][16][6], uint mode);


#endif