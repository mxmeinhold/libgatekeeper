## macOS

```sh
xcode-select --install
brew install libnfc libfreefare libgcrypt openssl@1.1 pkgconfig cmake
mkdir build
cd build
cmake -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl@1.1 ..

```

## arch linux

Install your dependencies (as of time of writing)
- In pacman repos: `libnfc libgcrypt openssl pkgconf cmake`
- `libfreefare`: there's an aur package `libfreefare-git`, but it tracks the git repo, and there are breaking changes since 0.4.0. I've built a usable package, available [here](https://drop.mxmeinhold.com/pkgs/libfreefare-0.4.0-1-x86_64.pkg.tar.zst) [[signature]](https://drop.mxmeinhold.com/pkgs/libfreefare-0.4.0-1-x86_64.pkg.tar.zst.sig) [[GPG key]](https://gpg.mxmeinhold.com). Otherwise you can manually install from [the git repo](https://github.com/nfc-tools/libfreefare/tree/libfreefare-0.4.0), making sure to use the `libfreefare-0.4.0` tag.

and in the root of the project run
```sh
mkdir build
cmake -S . -B build # This creates your build environment
cmake --build build # This actually builds your code
```

### USB-to-UART
Using a UART PN532 breakout with a USB-to-UART converter?
Install the appropriate driver (check System Profiler for the device manufacturer):

- [Silicon Labs CP210x](https://www.silabs.com/products/development-tools/software/usb-to-uart-bridge-vcp-drivers)
- [Prolific PL2303](http://www.prolific.com.tw/US/ShowProduct.aspx?p_id=229&pcid=41)

### Testing Setup
Running `nfc-list` should show:

```sh
nfc-list uses libnfc 1.7.1
NFC device: pn532_uart:/dev/tty.SLAB_USBtoUART opened
```

Or something similar, depending on your NFC reader.

Running `nfc-poll` and presenting a tag to the reader should print some metadata for the tag.
