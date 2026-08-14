# CherryRule Knowledge Provenance

ฐานความรู้นี้นำเข้าจาก `paddman/CherryRule` เพื่อให้ Hermes Agent ค้นหาและ
อธิบาย Rule เป็นภาษาไทยโดยไม่ต้องโหลด catalog ทั้งชุดเข้า prompt

## Source pin

| Field | Value |
|---|---|
| Source repository | `paddman/CherryRule` |
| Source ref | `recovery/catalog-source-20260814` |
| Source commit | `b38a9d17467e3ecf853b7232482c4b823a8a21ce` |
| Source artifact | `audit/cherry-rules.valid.json` |
| Source bundle | `dist/cherry-rules.bundle.yaml` |
| Bundle SHA-256 | `fce8f12183bdb1d796cabbbbda319704e283d6d6d998b1ea83284a252a364755` |
| Schema SHA-256 | `0416e821d800d337a6de0ee15c397b4d253e4b3dac264b6637daac58fa6dae35` |

## Validation result

- Rule ที่ประกาศ: 512
- Rule ที่อ่านได้: 512
- Rule ที่ผ่าน structural validation: 512
- Rule ID ซ้ำ: 0
- Regex ที่ตรวจด้วย RE2: 281
- Regex ที่ compile ไม่ผ่าน: 0
- Rule ที่มีภาษาไทยจาก source: 455
- Rule ที่ใช้ Thai fallback จากโครงสร้าง Rule: 57
- Rule ที่มีชุดคำอธิบายไทยพร้อมใช้งาน: 512

ไฟล์ `dist/cherry-rules.re2-catalog.json` ใน source recovery parse ไม่ผ่าน จึงไม่ถูก
ใช้เป็นฐานข้อมูล runtime การนำเข้าครั้งนี้สร้างจาก
`dist/cherry-rules.bundle.yaml` ที่ผ่าน schema และ RE2 validation แล้ว จากนั้นใช้
artifact สะอาด `audit/cherry-rules.valid.json`

## Runtime files

- `data/cherry-rules.th.json`: catalog ที่ agent ใช้งาน
- `data/provenance.json`: pin และ checksum ที่ตรวจด้วยโปรแกรม
- `scripts/cherry_rule.py`: CLI สำหรับค้นหา แสดง อธิบาย และ validate
- `SKILL.md`: กติกาการใช้ข้อมูลและรูปแบบคำตอบภาษาไทย

## Localization policy

สถานะ `native` หมายถึง `name_th` และ `description_th` มีภาษาไทยใน source

สถานะ `generated` หมายถึง source ใส่ข้อความอังกฤษไว้ในช่องภาษาไทย จึงสร้าง
fallback ภาษาไทยจาก category, phase, target, engine, operator, action และ field
อื่นที่ผ่าน validation พร้อมเก็บข้อความเดิมใน `source_name_th` และ
`source_description_th`

คำอธิบาย fallback ไม่ควรถูกนำเสนอว่าเป็นคำแปล official ที่ผ่าน human review
แต่ข้อมูลเชิงเทคนิคยังอ้างอิง field ของ Rule เดิมโดยตรง
