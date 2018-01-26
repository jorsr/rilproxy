RILProxy
=========
Program to proxy packets transmitted between Android's native radio interfaces
layer daemon (RILd) and the com.android.phone service. Traffic is intersected
at the `/dev/socket/rild` UNIX domain socket and forwarded via UDP. Socket path
and UDP port are configurable.

Additional control messages ensure that the RILd socket on the device providing
the radio functionality is opened *after* the socket has been opened on the
other device. This is required to ensure that the initial unsolicited startup
message from RILd is received by the phone process.

A rudimentary Wirkeshark dissector for the protocol run on `/dev/socket/rild` is
available in `scripts/dev/rilsocket.lua`. To install it run the follwing steps:

 - Get the the Android RIL source by `git clone https://android.googlesource.com/platform/hardware/ril`
 - Generate `ril_h.lua` with `./scripts/dev/convert_ril_h.py --output ril_h.lua /path/to/ril/source/.../include/telephony/ril.h`
 - Copy `ril_h.lua` and `rilsocket.lua` to the Wireshark plugins directory (which can be found in Wireshark under Help->About Wireshark->Directories->Personal Plugins)


Shortcomings/future work:

* Implement fragmentation for messages greater MTU (minus overhead)
* Signal direction through a flag
* Implement raw Ethernet transport in addition to UDP
* Dissect multiple RIL packets in one UDP message
* Dissect more protocol messages

(C) 2017, Alexander Senier <senier@componolit.com>

RILProxy Additions
===================
Scripts that are supposed to be run on the development machine can now be found under `scricps/dev`. These are:
* `convert_ril_h.py` Converts the CPP header file `ril.h` to a different language
* `demo_init.sh` Props the system for running the demo
* `demo_run.py` (Re-)starts the demo (including VM and phone)
* `rilbridge.sh` For bridging via shell script only
* `swbridge.py` Same as `swbrige`, combined with baseband firewall and `rilsocket.lua`

Changes to RILProxy scripts
---------------------------
* Added ability to transform `ril.h` into python via:

`./scripts/dev/convert_ril_h.py --output scripts/dev/ril_h.py /path/to/ril.h --python`
* Compared to `rilsocket.lua`, the python `dissector` module also uses one cache for each direction and handles ACK Parcels

Run the baseband demo
---------------------
Make sure that you are using the vendor RIL with RIL version < 13 (prior to build number NPD26.48-24-1, see [here](https://github.com/TheMuppets/proprietary_vendor_motorola/commits/cm-14.1/msm8916-common)).

Follow [Componolit GmbH's baseband demo guide](https://github.com/Componolit/componolit/blob/baseband_fw/run/baseband_demo.md). The VM should be called `Componolit`.

Install [Sismic](https://github.com/AlexandreDecan/sismic/) via `pip install sismic`. I recommend installing in a [virtual environment](https://docs.python.org/3/library/venv.html).

Go to development script folder `cd scripts/dev/`

Initialize the demo by running `./demo_init.sh <BP interface>` (CAREFUL `sudo` required).

Run the demo via `./demo_run.py`

© 2018, Joris Rau <Joris.Rau@tu-dresden.de>
