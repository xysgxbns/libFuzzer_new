#include <stdint.h>
#include <stddef.h>

bool FuzzMe(const uint8_t *Data, size_t DataSize) {
  return DataSize >= 3 &&
      Data[0] == 'X' &&
      Data[1] == 'X' &&
      Data[2] == 'O' &&
      Data[3] == 'L' &&
      Data[4] == 'M';  
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  FuzzMe(Data, Size);
  return 0;
}
