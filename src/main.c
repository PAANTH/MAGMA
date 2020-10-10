#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

const uint8_t gost_key[32] = {
                          0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
                          0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
                          0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
                          0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
                        };

const uint8_t magma_sboxes[8 *
                           16] = {
    // S-box pi_0
    12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1,
    // S-box pi_1
    6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15,
    // S-box pi_2
    11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0,
    // S-box pi_3
    12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11,
    // S-box pi_4
    7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12,
    // S-box pi_5
    5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0,
    // S-box pi_6
    8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7,
    // S-box pi_7
    1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2
};

/**
  \brief mem_dump Функция вывода на терминал дампа памяти.
  \param[in] addr Указатель на адрес в памяти.
  \param[in] len Длина в байтах.
*/
void mem_dump(const void *addr, size_t len)
{
  uint32_t a;
  uint32_t i;
  uint8_t c;

  printf("Memory review. Start %08X, len %08lX", (uint32_t)addr, len);

  if ((addr == NULL) || (len == 0)) {
    printf(" -- (null)\r\n");
    return;
  }

  a = 0;

  do {
    printf("\r\n%08X:", a);

    for (i = 0; i < 16; i++) {
      if (i < len) {
        printf(" %02X", *((const uint8_t *)addr + a + i));
      } else {
        printf("   ");
      }
    }

    printf(" ?");
    for (i = 0; i < 16; i++) {
      c = ' ';
      if (len != 0) {
        c = *((const uint8_t *)addr + a++);
        if (c < ' ') {
          c = 0x2E;  // '.'
        }
        len--;
      }
      printf("%c", c);
    }
    printf("?");
  } while (len != 0);

  printf("\r\n");
}

void mem_xor(const uint8_t *buf1_in, uint8_t *buf2_in_out, size_t len)
{
  for (size_t i = 0; i < len; i++) {
    buf2_in_out[i] = buf2_in_out[i] ^ buf1_in[i];
  }
}

void execute_substitute(uint8_t *buf)
{
  uint8_t four_bit[sizeof(uint32_t)*2] = {0};

  for (uint8_t i = 0; i < sizeof(uint32_t); i++) {
    four_bit[2 * i] = (buf[i] & 0xF0) >> 4;
    four_bit[2 * i + 1] = (buf[i] & 0x0F);
  }

  for(uint8_t i = 0; i < sizeof(uint32_t) * 2; i++) {
    uint8_t j = 7 - i;

    four_bit[i] = magma_sboxes[j * 16 + four_bit[i]];
  }

  for (uint8_t i = 0; i < sizeof(uint32_t); i++) {
    buf[i] = (four_bit[2*i] << 4) | four_bit[2*i + 1];
  }
}

/**
  \brief Always left-shift(to msb, whitch is at buf[0])
*/
void circular_shift(uint8_t *buf, uint8_t buf_len, uint8_t shift_bits)
{
  uint8_t sign;
  uint8_t shift_bytes = shift_bits/8;
  uint8_t shift_last_bits = shift_bits%8;
  uint8_t temp_storage[sizeof(uint32_t)] = {0};
  uint8_t carry = 0;
  uint8_t prev_carry = 0;

  //copy part that will be moved(only full bytes)
  memcpy(temp_storage, buf, shift_bytes);
  memmove(buf, &buf[shift_bytes], buf_len - shift_bytes);
  memcpy(&buf[buf_len - shift_bytes], temp_storage, shift_bytes);

  if (shift_last_bits == 0) {
    return;
  }

  prev_carry = buf[0] >> (8 - shift_last_bits);
  for (uint8_t i = 0; i < buf_len; i++) {
    carry = buf[buf_len - 1 - i] >> (8 - shift_last_bits);
    buf[buf_len - 1 - i] = buf[buf_len - 1 - i] << shift_last_bits;
    buf[buf_len - 1 - i] |= prev_carry;
    prev_carry = carry;
  }

}

void invert_byte_order(uint8_t *buf, uint8_t buf_len)
{ uint8_t carry = 0;

  for (int i = 0; i < buf_len/2; i++) {
    carry = buf[i];
    buf[i] = buf[buf_len - 1 - i];
    buf[buf_len - 1 - i] = carry;
  }
}

void execute_iteration(uint8_t *A1, uint8_t *A0, uint8_t *K, uint8_t last_iter)
{
  uint32_t temp;
  uint8_t raw[sizeof(uint32_t)];
  uint8_t out[sizeof(uint32_t)];

  // Addition K1 and A0
  invert_byte_order(K, sizeof(uint32_t));
  invert_byte_order(A0, sizeof(uint32_t));
  temp = *(uint32_t *)K + *(uint32_t *)A0;
  memcpy(raw, &temp, sizeof(uint32_t));
  invert_byte_order(raw, sizeof(uint32_t));
  invert_byte_order(A0, sizeof(uint32_t));

  //subst and xor
  execute_substitute(raw);
  circular_shift(raw, sizeof(uint32_t), 11);
  mem_xor(A1, raw, sizeof(uint32_t));

  if (last_iter) {
    memcpy(A1, raw, sizeof(uint32_t));
  } else {
    memcpy(A1, A0, sizeof(uint32_t));
    memcpy(A0, raw, sizeof(uint32_t));
  }
}

void get_a_parts(const uint8_t *text_block, uint8_t *A1, uint8_t *A0)
{
  memcpy(A1, text_block, sizeof(uint32_t));
  memcpy(A0, &text_block[sizeof(uint32_t)], sizeof(uint32_t));
}

void get_iteration_key(uint8_t *k_iter, const uint8_t *key, uint8_t key_num)
{
  uint8_t pos;

  if (key_num < 24) {
    pos = key_num % (32 / sizeof(uint32_t));
  } else {
    pos = 31 - key_num;
  }

  pos *= sizeof(uint32_t);

  memcpy(k_iter, &key[pos], sizeof(uint32_t));
}

void encrypt_block(const uint8_t *text_block, const uint8_t *key, uint8_t *cipher_text_block)
{
  uint8_t k_iter[sizeof(uint32_t)];
  uint8_t A0[sizeof(uint32_t)];
  uint8_t A1[sizeof(uint32_t)];

  get_a_parts(text_block, A1, A0);

  for (int i = 0; i < 32; i++) {
    get_iteration_key(k_iter, key, i);
    if (i < 31) {
      execute_iteration(A1, A0, k_iter, 0);
    } else {
      execute_iteration(A1, A0, k_iter, 1);
    }
  }


  memcpy(cipher_text_block, A1, sizeof(uint32_t));
  memcpy(&cipher_text_block[sizeof(uint32_t)], A0, sizeof(uint32_t));
}

void decrypt_block(const uint8_t *cipher_text_block, const uint8_t *key, uint8_t *text_block)
{
  uint8_t k_iter[sizeof(uint32_t)];
  uint8_t A0[sizeof(uint32_t)];
  uint8_t A1[sizeof(uint32_t)];

  get_a_parts(cipher_text_block, A1, A0);

  for (int i = 0; i < 32; i++) {
    get_iteration_key(k_iter, key, 31 - i);
    if (i < 31) {
      execute_iteration(A1, A0, k_iter, 0);
    } else {
      execute_iteration(A1, A0, k_iter, 1);
    }
  }


  memcpy(text_block, A1, sizeof(uint32_t));
  memcpy(&text_block[sizeof(uint32_t)], A0, sizeof(uint32_t));
}

static void print_help(const char *prog)
{
    printf(
        "Usage:\n"
        "  %s -e -i input_filename -o output_file_name -k key_file_name\n"
        "Parameters:\n"
        "  -e encrypt input file and write result to output file\n"
        "  -d decrypt input file and write result to output file\n"
        "  -i input filename\n"
        "  -o output filename\n"
        "  -k key filename (must be binary file)\n"
        "  -g generate key file\n"
        "Example:\n"
        "  %s -e -ifilein.txt -ofileout.txt -kfilekey.bin\n",
        prog, prog);
}

uint64_t file_size(char *filename)
{
  struct stat st;
  int err;

  err = stat(filename, &st);

  if (err) {
    printf("Error determine file size!\n");
    return 0;
  }

  return st.st_size;
}

void get_rand_key(uint8_t *key_buf)
{
  for(uint8_t i = 0; i < 32; i++) {
    key_buf[i] = rand() % 0xFF;
  }
}

int main(int argc, char * const argv[])
{
  int ret;
  char *input_file_name = NULL;
  char *output_file_name = NULL;
  char *key_file_name = NULL;
  uint8_t key[32];
  uint64_t padding_bytes;
  uint64_t input_fsize = 0;
  uint8_t encrypt = 1;
  uint8_t text_block[sizeof(uint64_t)] = {0}; //{0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
  uint8_t result_block[sizeof(uint64_t)] = {0};
  uint64_t write_counter = 0;
  uint8_t generate_key = 0;

  FILE *fp_in;
  FILE *fp_out;
  FILE *fp_key;

  while ((ret = getopt(argc, argv, "gedi:o:k:")) != -1) {
    switch (ret) {
      case 'g':
        generate_key = 1;
        break;
      case 'e':
        encrypt = 1;
        break;
      case 'd':
        encrypt = 0;
        break;
      case 'i':
        input_file_name = optarg;
        break;
      case 'o':
        output_file_name = optarg;
        break;
      case 'k':
        key_file_name = optarg;
        break;
    default:
        print_help(argv[0]);
        return 0;
    }
  }

  if(generate_key) {
    key_file_name = "key.bin";
    fp_key = fopen(key_file_name, "w");
    get_rand_key(key);
    fwrite(key, sizeof(uint8_t), 32, fp_key);
    fclose(fp_key);
    printf("Key file is successfully written\n");
    return 0;
  }

  if (input_file_name == NULL) {
    printf("No input file name!\n");
    goto end;
  }

  if (output_file_name == NULL) {
    printf("No output file name!\n");
    goto end;
  }

  if (key_file_name == NULL) {
    printf("No key file name!\n");
    printf("Using internal gost key\n");
    memcpy(key, gost_key, 32);
    //goto end;
  } else {
    fp_key = fopen(key_file_name, "r");
    fread(key, sizeof(uint8_t), 32, fp_key);
    fclose(fp_key);
  }

  fp_in = fopen(input_file_name, "r");
  fp_out = fopen(output_file_name, "w");


  input_fsize = file_size(input_file_name);
  if (input_fsize == 0) {
    goto fend;
  }
  printf("Input file size is %lu\n", input_fsize);

  if (encrypt) { // write count of padding bytes
    padding_bytes = input_fsize % sizeof(uint64_t);
    if (padding_bytes) {
      padding_bytes = sizeof(uint64_t) - padding_bytes;
    }
    fwrite(&padding_bytes, sizeof(padding_bytes),1, fp_out);
  } else { // read count of padding bytes
    fread((uint8_t *)&padding_bytes, sizeof(padding_bytes), 1, fp_in);
    printf("Padding bytes to avoid %lu\n", padding_bytes);
  }

  while(1) {
    uint64_t write_amount = sizeof(uint64_t);
    uint64_t read_amount = sizeof(uint64_t);
    memset(text_block, 0xFF, sizeof(uint64_t));


    read_amount = fread(text_block, sizeof(uint8_t), sizeof(uint64_t), fp_in);
    if (read_amount == 0) {
      break;
    }

    if (encrypt) {
      encrypt_block(text_block, key, result_block);
    } else {
      decrypt_block(text_block, key, result_block);
      write_counter += sizeof(uint64_t);
      if (write_counter >= (input_fsize - padding_bytes - sizeof(padding_bytes))) {
        write_amount = write_amount - padding_bytes;
        printf("write_amount %lu\n", write_amount);
      }
    }

    fwrite(result_block, sizeof(uint8_t), write_amount, fp_out);
  }

fend:
  fclose(fp_in);
  fclose(fp_out);

end:
  return 0;
}
