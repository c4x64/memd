#!/system/bin/sh
# Load rwbridge with FRESH kallsyms addresses (kernel may be KASLR re-based
# after reboot, so never hardcode). Run as root.
#
# Usage: sh load_rwbridge.sh

K=/proc/kallsyms
KO=/data/local/tmp/rwbridge.ko

get() {
    grep " $1$" $K | awk '{print $1}'
}

FTVP=$(get find_task_by_vpid)
GTM=$(get get_task_mm)
MMP=$(get mmput)
ARM=$(get access_remote_vm)
RWH=$(get register_wide_hw_breakpoint)
UWH=$(get unregister_wide_hw_breakpoint)
SDW=$(get schedule_delayed_work)
CDW=$(get cancel_delayed_work_sync)

echo "find_task_by_vpid=$FTVP"
echo "get_task_mm=$GTM"
echo "mmput=$MMP"
echo "access_remote_vm=$ARM"
echo "register_wide_hw_breakpoint=$RWH"
echo "unregister_wide_hw_breakpoint=$UWH"
echo "schedule_delayed_work=$SDW"
echo "cancel_delayed_work_sync=$CDW"

if [ -z "$FTVP" ] || [ -z "$GTM" ] || [ -z "$MMP" ] || [ -z "$ARM" ]; then
    echo "ERROR: missing core symbol(s)"
    exit 1
fi

rmmod rwbridge 2>/dev/null
insmod $KO \
    find_task_by_vpid=0x$FTVP \
    get_task_mm=0x$GTM \
    mmput=0x$MMP \
    access_remote_vm=0x$ARM \
    register_wide_hw_breakpoint=0x$RWH \
    unregister_wide_hw_breakpoint=0x$UWH \
    schedule_delayed_work=0x$SDW \
    cancel_delayed_work_sync=0x$CDW
echo "insmod rc=$?"
grep rwbridge /proc/modules
