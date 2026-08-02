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
RWH=$(get register_user_hw_breakpoint)
REL=$(get perf_event_release_kernel)
PEL=$(get perf_event_enable)
KTC=$(get kthread_create_on_node)
WUP=$(get wake_up_process)
KTS=$(get kthread_should_stop)
KTST=$(get kthread_stop)
MSP=$(get msleep)

echo "find_task_by_vpid=$FTVP"
echo "get_task_mm=$GTM"
echo "mmput=$MMP"
echo "access_remote_vm=$ARM"
echo "register_user_hw_breakpoint=$RWH"
echo "perf_event_release_kernel=$REL"
echo "perf_event_enable=$PEL"
echo "kthread_create_on_node=$KTC"
echo "wake_up_process=$WUP"
echo "kthread_should_stop=$KTS"
echo "kthread_stop=$KTST"
echo "msleep=$MSP"

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
    register_user_hw_breakpoint=0x$RWH \
    perf_event_release_kernel=0x$REL \
    perf_event_enable=0x$PEL \
    kthread_create_on_node=0x$KTC \
    wake_up_process=0x$WUP \
    kthread_should_stop=0x$KTS \
    kthread_stop=0x$KTST \
    msleep=0x$MSP
echo "insmod rc=$?"
grep rwbridge /proc/modules
