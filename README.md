##### This is IoT security Testing framework developed by first semester students studying Msc. Cyber Security in Aalborg University, Denmark.

#### Author
nullX-byte

# Pentagon
This is an automated framework that does the following task:
- Network/host scanning (open ports, service detection, OS detection)
- Captures wireless traffic (both bluetooth and wifi)
      - Gives user flexibility to choose between Managed mode or Monitor mode(Depends on hardware)
- ARP spoofing
- Flooding traffic to a host

### Installation
#### Prerequisites
Make sure you have the following installed in your system:
* **Python 3.4 or greater**
* **pip**
* **Wireshark**
* **Nmap**
* **dsniff**
* **Scapy** (installed via pip with requirements.txt)
  
Run:
`sudo python setup.py install` 

This command will install and create an executable file named pentagon which you can run directly from the terminal. 

---

### WiFi Monitor Mode — rtl8812au Driver

The wireless sniffing feature requires a WiFi adapter that supports monitor mode.
Many common USB adapters (e.g. Alfa AWUS036ACH) use the **rtl8812au** (8812AU / 8821AU) chipset and need an out-of-tree kernel driver installed via DKMS.

#### Installing the driver

```bash
# Install build prerequisites
sudo apt install dkms git build-essential linux-headers-$(uname -r)

# Clone the aircrack-ng fork of the driver
sudo git clone https://github.com/aircrack-ng/rtl8812au.git \
    /usr/src/rtl8812au-5.13.6-23

# Register and build with DKMS
sudo dkms add    -m rtl8812au -v 5.13.6-23
sudo dkms build  -m rtl8812au -v 5.13.6-23
sudo dkms install -m rtl8812au -v 5.13.6-23

# Load the module
sudo modprobe 88XXau
```

#### Fixing DKMS build failures on kernel 6.x

On **kernel 6.x** (including `6.19.6+parrot7-amd64`) the DKMS build fails with:

```
fatal error: drv_types.h: No such file or directory
```

**Root cause:** Starting with kernel 6.x, the out-of-tree Kbuild system no
longer guarantees that `$(src)` is set to the module source directory.  The
driver Makefile relies on `$(src)` to construct `EXTRA_CFLAGS` include
paths, so the compiler cannot find the driver-private headers
(`drv_types.h`, `hal_data.h`, …) that live in the source root.

**Fix:** A small guard block is inserted near the top of the driver Makefile
that falls back to `$(M)` (always set by kbuild/DKMS) when `$(src)` is
empty. A helper script is provided to apply the patch and rebuild automatically:

```bash
# Run from the repository root after installing the driver (see above)
sudo bash drivers/rtl8812au/fix_dkms_build.sh

# To target a specific kernel version:
sudo bash drivers/rtl8812au/fix_dkms_build.sh --kernel 6.19.6+parrot7-amd64
```

The script:
1. Backs up the original Makefile before modifying it.
2. Inserts the `$(src)` fallback guard if not already present.
3. Removes any stale DKMS build artefacts for the target kernel.
4. Runs `dkms build` and `dkms install` for the target kernel.

###
