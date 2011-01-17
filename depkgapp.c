/*
depkgapp 1.0 by lcemonkey

Utility to decrypt and extract Playstation 3, Playstation Portable and mixed
game packages onto your PC.

usage:

./depkgapp [PKG_NAME]

Based on code provided by Mathieulh

*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <stdint.h>
#include <math.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <dirent.h>
#include <errno.h>

typedef struct __fileentry
{
  unsigned int location;
  unsigned int namelength;
  unsigned int offset;
  unsigned long filesize;
  unsigned char contenttype;
  unsigned char filetype;
  char filename[256];
} fileentry;

unsigned char Aeskey[16];

// PSP
unsigned char PSPAesKey[] = {
  0x07, 0xF2, 0xC6, 0x82, 0x90, 0xB5, 0x0D, 0x2C,
  0x33, 0x81, 0x8D, 0x70, 0x9B, 0x60, 0xE6, 0x2B
};

// PS3
unsigned char PS3AesKey[] = {
  0x2E, 0x7B, 0x71, 0xD7, 0xC9, 0xC9, 0xA1, 0x4E,
  0xA3, 0x22, 0x1F, 0x18, 0x88, 0x28, 0xB8, 0xF8
};

unsigned char PKGFileKey[16];

void reversearray(unsigned char *orig)
{
  int inner, outer = sizeof(orig)-1;
  unsigned char temp;

  for(inner=0;inner<outer;inner++, outer--)
  {
    temp = orig[inner];
    orig[inner] = orig[outer];
    orig[outer] = temp;
  }
}

int removedirectory(const char *dirname)
{
  DIR *dir;
  struct dirent *entry;
  char path[PATH_MAX];

  dir = opendir(dirname);
  if(dir==NULL)
  {
    perror("Error opendir()");
    return 0;
  }

  while((entry = readdir(dir))!=NULL)
  {
    if(strcmp(entry->d_name, ".") && strcmp(entry->d_name, ".."))
    {
      snprintf(path, (size_t) PATH_MAX, "%s/%s", dirname, entry->d_name);
      if(entry->d_type == DT_DIR)
      {
        removedirectory(path);
      }
      remove(path);
    }
  }
  closedir(dir);
  snprintf(path, (size_t) PATH_MAX, "%s", dirname);
  rmdir(path);
  return 0;
}

unsigned int bytestoint32(unsigned char *bytes)
{
  unsigned int value = 0;
  value = bytes[0] << 24;
  value += bytes[1] << 16;
  value += bytes[2] << 8;
  value += bytes[3];
  return value;
}

int file_exists(const char * filename)
{
  struct stat st;
  if(stat(filename, &st)==0)
  {
    return 1;
  }
  return 0;
}

int IncrementArray(unsigned char *SourceArray, int position)
{
  if(SourceArray[position]==0xFF)
  {
    if(position!=0)
    {
      if(IncrementArray(SourceArray, position-1))
      {
        SourceArray[position]=0x00;
        return 1;
      }
      else
      {
        return 0; // Maximum rached yet
      } 
    }
    else
    {
      return 0; // Maximum reached yet
    }
  }
  else
  {
    SourceArray[position]+=0x01;
    return 1;
  }
}

void arraycopy(unsigned char *dest, long doffset, unsigned char *source, long soffset, long length)
{
  long counter;
  for(counter=0;counter<length;counter++)
  {
    dest[doffset+counter] = source[soffset+counter];
  }
}

void xorengine(unsigned char *input, unsigned char *output, int length, unsigned char *mask)
{
  int i=0;
  for(i=0;i<length;i++)
  {
    output[i]=input[i]^mask[i];
  }
}

int DecryptPKGFile(char PKGFilename[])
{

  int moltiplicator = 65536;
  unsigned char EncryptedData[sizeof(Aeskey) * moltiplicator];
  unsigned char DecryptedData[sizeof(Aeskey) * moltiplicator];

  unsigned char PKGXorKey[sizeof(Aeskey)];
  unsigned char EncryptedFileStartOffset[4];
  unsigned char EncryptedFileLength[4];

  unsigned int uiEncryptedFileStartOffset = 0;
  unsigned int uiEncryptedFileLength = 0;

  FILE *PKGReadStream;
  FILE *PKGWriteStream;
  
  PKGReadStream = fopen(PKGFilename, "rb");
  fseek(PKGReadStream, 0x00, 0); 
  unsigned char pkgMagic[4];
  fread(pkgMagic, 4, 1, PKGReadStream);

  if(pkgMagic[0x00] != 0x7F || pkgMagic[0x01] != 0x50 || pkgMagic[0x02] != 0x4B || pkgMagic[0x03] != 0x47)
  {
    printf("Selected file isn't a Pkg file!\n");
    fclose(PKGReadStream);
    return 1;
  }

  // Finalized byte
  unsigned char pkgFinalized[1];
  fseek(PKGReadStream, 0x04, SEEK_SET);
  fread(pkgFinalized, 1, 1, PKGReadStream);
  if(pkgFinalized[0] != 0x80)
  {
    printf("Selected file is a debug PS3/PSP pkg!\nOnly retail packages are supported.\n");
    fclose(PKGReadStream);
    return 2;
  }

  // PKG type PSP/PS3
  fseek(PKGReadStream, 0x07, SEEK_SET);
  unsigned char pkgType[1];
  fread(pkgType, 1, 1, PKGReadStream);
  switch(pkgType[0])
  {
    case 0x01:
      // PS3
      memcpy(Aeskey, PS3AesKey, sizeof(PS3AesKey));
      break;
    case 0x02:
      //PSP
      memcpy(Aeskey, PS3AesKey, sizeof(PSPAesKey));
      break;
    default:
      printf("Selected file isn't a valid PS3/PSP package!\n");
      fclose(PKGReadStream);
      return 3;
  }
   
  // 0x24 store the start address of the encrypted file to decrypt
  fseek(PKGReadStream, 0x24, SEEK_SET);
  fread(EncryptedFileStartOffset, (int)sizeof(EncryptedFileStartOffset), 1, PKGReadStream);
  //reversearray(EncryptedFileStartOffset);
  uiEncryptedFileStartOffset = bytestoint32(EncryptedFileStartOffset);

  //0x1C store the length of the whole pkg file

  //0x2C 
  fseek(PKGReadStream, 0x2C, SEEK_SET);
  fread(EncryptedFileLength, sizeof(EncryptedFileLength), 1, PKGReadStream);
  //reversearray(EncryptedFileLength);
  uiEncryptedFileLength = bytestoint32(EncryptedFileLength);

  //0x70 Store the PKG file key
  fseek(PKGReadStream, 0x70, SEEK_SET);
  fread(PKGFileKey, sizeof(PKGFileKey), 1, PKGReadStream);
  unsigned char incPKGFileKey[16];
  memcpy(incPKGFileKey, PKGFileKey, sizeof(PKGFileKey));

  // the "file" key at 0x70 have to be encrypted with a "global AES key"
  // to generate the "xor" key
  // PSP uses CipherMode.ECB, pPaddingMode,none that doesn't need IV
  AES_KEY AES_Encrypt_Key;
  AES_set_encrypt_key(Aeskey, 128, &AES_Encrypt_Key);
  AES_ecb_encrypt(PKGFileKey, PKGXorKey, &AES_Encrypt_Key, AES_ENCRYPT);

  // Pieces calculation
  double division = (double)uiEncryptedFileLength / sizeof(Aeskey);
  uint64_t pieces = (uint64_t)floor(division);
  uint64_t mod = (uint64_t)uiEncryptedFileLength / (uint64_t)sizeof(Aeskey);
  if(mod > 0)
  {
    pieces += 1;
  }
  char DecryptedFilename[260];
  sprintf(DecryptedFilename, "%s.Dec", PKGFilename);
  if(file_exists(DecryptedFilename))
  {
    remove(DecryptedFilename);
  }

  // Write File
  PKGWriteStream = fopen(DecryptedFilename, "wb");
  
  // Put the read pointer on the encrypted starting point
  fseek(PKGReadStream, (int)uiEncryptedFileStartOffset, SEEK_SET);

  // pieces calculation
  double filedivision = (double)uiEncryptedFileLength / (double)(sizeof(Aeskey)*moltiplicator);
  uint64_t filepieces = (uint64_t)floor(filedivision);
  uint64_t filemod = (uint64_t)uiEncryptedFileLength % (uint64_t)(sizeof(Aeskey)*moltiplicator);
  if(filemod>0)
  {
    filepieces+=1;
  }

  uint64_t i=0;
  uint64_t EncryptedDataLength = sizeof(EncryptedData);
  for(i=0;i<filepieces;i++)
  {
    // if we had a mod and this is the last piece then...
    if((filemod>0)&&(i==(filepieces-1)))
    {
      EncryptedDataLength = filemod;
    }
    // read 16 bytes of Encrypted Data
    fread(EncryptedData, EncryptedDataLength, 1, PKGReadStream);

    // in order to retrieve a fast AES Encryption we pre-increment the array
    unsigned char PKGFileKeyConsec[sizeof(EncryptedData)];
    unsigned char PKGXorKeyConsec[sizeof(EncryptedData)];

    int pos = 0;
    for(pos=0; pos<EncryptedDataLength;pos+=sizeof(Aeskey))
    {
      memcpy(PKGFileKeyConsec+pos, incPKGFileKey, sizeof(PKGFileKey));
      IncrementArray(incPKGFileKey, sizeof(PKGFileKey)-1);
    }

    // PSP uses ciphermode.ECB, paddingmode.None that doesn't need IV
    AES_KEY AES_Encrypt_Key_Consec;
    AES_set_encrypt_key(Aeskey, 128, &AES_Encrypt_Key_Consec);
    int counter=0;
    for(counter=0;counter<sizeof(PKGFileKeyConsec);counter+=sizeof(Aeskey))
    {
      AES_ecb_encrypt(PKGFileKeyConsec+counter, PKGXorKeyConsec+counter, &AES_Encrypt_Key_Consec, AES_ENCRYPT);
    }

    // XOR decrypt and save every 16 bytes of data
    xorengine(EncryptedData, DecryptedData, sizeof(PKGXorKeyConsec), PKGXorKeyConsec);

    fwrite(DecryptedData, EncryptedDataLength,1, PKGWriteStream);
  }

  // close all open files
  fclose(PKGWriteStream);
  fclose(PKGReadStream);

  return 0;
}

int DecryptData(int dataSize, long dataRelativeOffset, long pkgEncryptedFileStartOffset, unsigned char *Aeskey, FILE *encrPKGReadStream, unsigned char *DecryptedDataOutput)
{
  int size = dataSize % 16;
  if(size>0)
  {
    size = ((dataSize / 16) + 1)* 16;
  }
  else
  {
    size = dataSize;
  }

  unsigned char EncryptedData[size];
  unsigned char DecryptedData[size];
  unsigned char PKGFileKeyConsec[size];
  unsigned char PKGXorKeyConsec[size];
  unsigned char incPKGFileKey[sizeof(PKGFileKey)];
  memcpy(incPKGFileKey, PKGFileKey, sizeof(PKGFileKey));

  fseek(encrPKGReadStream, dataRelativeOffset + pkgEncryptedFileStartOffset, SEEK_SET);
  fread(EncryptedData, size, 0, encrPKGReadStream);

  int pos = 0;
  for(pos=0;pos<size;pos+=16)
  {
    IncrementArray(incPKGFileKey, sizeof(PKGFileKey)-1);
  }

  for(pos=0;pos<size;pos+=16)
  {
    memcpy(PKGFileKeyConsec+pos, incPKGFileKey, sizeof(PKGFileKey));
    IncrementArray(incPKGFileKey, sizeof(PKGFileKey)-1);
  }
  
  // the "file" key at 0x70 have to be encrypted with a "global AES key"
  // to generate the "xor" key
  // PSP uses CipherMode.ECB, pPaddingMode,none that doesn't need IV
  AES_KEY AES_Encrypt_Key;
  AES_set_encrypt_key(Aeskey, 128, &AES_Encrypt_Key);
  AES_ecb_encrypt(PKGFileKeyConsec, PKGXorKeyConsec, &AES_Encrypt_Key, AES_ENCRYPT);
     
  // XOR decrypt and save every 16 bytes of data
  xorengine(EncryptedData, DecryptedData, sizeof(PKGXorKeyConsec), PKGXorKeyConsec);

  return 0;
}

int pkgfilecount(char decryptedPKGFilename[])
{
  unsigned char buffer[320000];
  unsigned char firstNameOffset[4];
  int filecount = 0;

  FILE *decryptedPKGStream;

  decryptedPKGStream = fopen(decryptedPKGFilename, "rb");

  fseek(decryptedPKGStream, 0, SEEK_SET);
  fread(buffer, sizeof(buffer), 1, decryptedPKGStream);

  // retrieve 1st file name offset location
  memcpy(firstNameOffset, buffer, sizeof(firstNameOffset));
  unsigned int uifirstNameOffset = bytestoint32(firstNameOffset);

  // determine file count based on 1st filename offset location
  filecount = uifirstNameOffset / 32;

  return filecount;
}

fileentry fileinfo(char decryptedFilename[], int index)
{
  fileentry entry;
  FILE *decryptedFileStream;
  unsigned char buffer[32];

  decryptedFileStream = fopen(decryptedFilename, "rb");

  // read file entry bytes
  fseek(decryptedFileStream, index*32, SEEK_SET);
  fread(buffer, sizeof(buffer), 1, decryptedFileStream);

  // table:
  //0-3       4-7	 8-11  12-15     16-19 20-23	  24-27	     28-31
  //|name loc||name size||NULL||file loc||NULL||file size||cont type||NULL| 
  entry.location = (buffer[0]<<24)+(buffer[1]<<16)+(buffer[2]<<8)+buffer[3];
  entry.namelength = (buffer[4]<<24)+(buffer[5]<<16)+(buffer[6]<<8)+buffer[7];
  entry.offset = (buffer[12]<<24)+(buffer[13]<<16)+(buffer[14]<<8)+buffer[15];
  entry.filesize = (buffer[20]<<24)+(buffer[21]<<16)+(buffer[22]<<8)+buffer[23];
  entry.contenttype = buffer[24];
  entry.filetype = buffer[27];

  // retrieve filename
  fseek(decryptedFileStream, entry.location, SEEK_SET);
  fread(entry.filename, entry.namelength, 1, decryptedFileStream);   
  entry.filename[entry.namelength] = '\0';
  
  fclose(decryptedFileStream);  
  return entry;
}

int extractfile(fileentry entry, char *pkgfile, char *outputdir)
{
  char filename[256];
  FILE *decryptedPKGStream;
  FILE *outputfile;

  sprintf(filename, "%s/%s", outputdir, entry.filename);
  if((entry.filetype==0x04)&&(entry.filesize==0))
  {
    if(mkdir(filename, 0755)!=0)
    {
      printf("Error creating directory %s.\n", filename);
    }
  }
  else
  {
    // contenttype == 0x90 = PSP file/dir
    if(entry.contenttype==0x90)  // psp file/dir
    {
      
    }
    if((entry.contenttype==0x80)||(entry.contenttype==0x00))  // ps3 file/dir
    {
      unsigned char buffer[1048576];
      long blocks = floor(entry.filesize / 1048576);
      int leftover = entry.filesize % 1048576;
      int writelength = 1048576;
      long counter = 0;

      // add 1 block if leftover > 0
      if(leftover>0)
      {
        blocks++;
      }
    
      decryptedPKGStream = fopen(pkgfile, "rb");
      outputfile = fopen(filename, "wb");
      for(counter=0;counter<=blocks;counter++)
      {
        if(counter==blocks)
        {
          writelength = leftover;
        }
        fseek(decryptedPKGStream, entry.offset, SEEK_SET);
        fread(buffer, writelength, 1, decryptedPKGStream);
        fwrite(buffer, writelength, 1, outputfile);
      }
      fclose(decryptedPKGStream);
      fclose(outputfile);
    }
  }
  return 0;
}

int ExtractFiles(char decryptedPKGFilename[])
{
  char WorkDir[PATH_MAX] = "\0";

  sprintf(WorkDir, "%s.EXT", decryptedPKGFilename);

  int uiFileNr = 0;

  // get the pkg file count 
  uiFileNr = pkgfilecount(decryptedPKGFilename);

  // read file table info
  fileentry pkgfiles[uiFileNr];
  int counter = 0;
  for(counter=0;counter<uiFileNr;counter++)
  {
    pkgfiles[counter] = fileinfo(decryptedPKGFilename, counter);
  }

  // make work dirctory
  if(!file_exists(WorkDir))
  {
    mkdir(WorkDir, 0755);
  }
  else
  {
    // remove old workdir first
    if(removedirectory(WorkDir)!=0)
    {
      printf("Error removing previously found %s!\n", WorkDir);
      return 1;
    }
    else
    {
      mkdir(WorkDir, 0755);
    }
  }

  // extract package files
  for(counter=0;counter<uiFileNr;counter++)
  {
    extractfile(pkgfiles[counter], decryptedPKGFilename, WorkDir);
  }
  return 0;
}

void usage()
{
  printf("Usage:\n\n");
  printf("depkgapp [PKG_NAME]\n\n");
}

int main(int argc, char* argv[])
{
  char DecryptedFilename[256] = "";

  if(argc==2)
  {
    DecryptPKGFile(argv[1]);
    sprintf(DecryptedFilename, "%s.Dec", argv[1]);
    ExtractFiles(DecryptedFilename);
  }
  else
  {
    usage();
  }

  return 0; 
}
