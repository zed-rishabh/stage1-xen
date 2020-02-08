#!/bin/sh

mountPointLineNo=1
ls /sys/block/ | grep xvd | while read -r disk ; do
  echo "Processing $disk"
  targetDir=$(sed "${mountPointLineNo}q;d" /mnt/mountPoints)
  if [ -z "$targetDir" ]
    then
      echo "Error while mounting: No Mount-Point found for $disk."
      exit 0
  fi
  #Fetching Major and Minor device
  IN=$(cat /sys/block/$disk/dev | tr ":" "\n")
  major=$(echo ${IN} | cut -d' ' -f1)
  minor=$(echo ${IN} | cut -d' ' -f2)

  #Creating a block device under /dev with Major and minor devices
  echo "Creating device file /dev/$disk"
  mknod /dev/$disk b $major $minor && \
  echo "Successfully created device file for /dev/$disk" || \
  echo "Failed to create device file for /dev/$disk"
  echo

  #Creating a file system inside the partition
  fileSystem="vfat"
  echo "Creating $fileSystem file system on /dev/$disk"
  mkfs.$fileSystem /dev/$disk && \
  echo "Successfully created $fileSystem file system on /dev/$disk" || \
  echo "Failed to create $fileSystem file system on /dev/$disk"
  echo

  #Mounting the partition onto a target directory
  diskAccess=$(cat /sys/block/$disk/ro)
  if [ $diskAccess -eq 0 ]; then
    accessRight=rw
  else
    accessRight=ro
  fi
  stage2TargetPath="/mnt/rootfs"$targetDir
  echo "Mounting /dev/$disk on $stage2TargetPath with access: $accessRight"
  mkdir -p $stage2TargetPath
  mount -O remount,$accessRight /dev/$disk $stage2TargetPath && \
  echo "Successfully mounted file system:/dev/$disk on $targetDir" || \
  echo "Failed to mount file system:/dev/$disk on $targetDir"

  mountPointLineNo=$(expr $mountPointLineNo + 1)
done
