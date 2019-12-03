## macOS

```sh
xcode-select --install
brew install libnfc libfreefare libgcrypt openssl@1.1 pkgconfig cmake
mkdir build
cd build
cmake -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl@1.1 ..

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