#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// Bootstrap entry point placeholder. Replace after entry path reconstruction.
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
  return 0;
}
#else
int main() {
  return 0;
}
#endif
