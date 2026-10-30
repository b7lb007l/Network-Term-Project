#!/bin/bash
# สำรองข้อมูล WordPress: database + ไฟล์เว็บ เก็บย้อนหลัง 7 วัน
set -e
DEST="/var/backups/wordpress"
DATE=$(date +%F)

mkdir -p "$DEST"
chmod 700 "$DEST"

# สำรอง database (root ของ MySQL เข้าผ่าน auth_socket ไม่ต้องใช้รหัสผ่าน)
mysqldump --single-transaction --no-tablespaces wordpress | gzip > "$DEST/db-$DATE.sql.gz"

# สำรองไฟล์เว็บทั้งหมด รวมรูปที่อัปโหลด ธีม และปลั๊กอิน
tar czf "$DEST/files-$DATE.tar.gz" -C /var/www betterson

# ลบไฟล์ที่เก่ากว่า 7 วัน
find "$DEST" -type f -mtime +6 -delete

echo "backup เสร็จ: $DEST"
