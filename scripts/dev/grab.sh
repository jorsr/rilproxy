# push proxy ril to device
adb root
sleep 3
adb remount
adb push /home/g/android/lineage/out/target/product/harpia/obj/lib/libril-proxy-1.so /system/lib
adb push ~/android/lineage/hardware/ril/proxy-ril/props.sh /system/bin
adb shell pkill rild
