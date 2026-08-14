---
name: cherry-rule
description: "Search, inspect, and explain all 512 CherryRule WAF, API, cloud, bot, privacy, and AI-agent security rules in detailed Thai using the bundled validated catalog."
version: 1.0.0
author: paddman
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [security, waf, api-security, cherry-rule, rule-explanation, thai, re2, virtual-patch]
    related_skills: [cherry-pcap]
---

# CherryRule Thai Knowledge

ใช้ skill นี้เมื่อผู้ใช้ต้องการค้นหา อ่าน ตรวจสอบ เปรียบเทียบ ปรับแต่ง หรืออธิบาย
CherryRule รวมถึงเมื่อ event, alert, WAF log หรือ incident อ้างถึง Rule ID เช่น
`CWAF-GUI-200001`

ฐานความรู้ที่รวมมากับ skill มี 512 Rule จาก `paddman/CherryRule` ครอบคลุม HTTP,
injection, server-side attacks, API และ identity, bot และ business abuse,
cloud/DevOps, response privacy, AI/LLM/agent security, threat intelligence และ
virtual patch

## หลักบังคับ

1. ดึงข้อมูล Rule จาก CLI หรือ catalog ที่รวมมากับ skill ทุกครั้ง อย่าตอบจากความจำ
   ของโมเดลเมื่อมี Rule ID หรือค่าทางเทคนิคเฉพาะ
2. อธิบายเป็นภาษาไทย โดยคงค่า technical field ตามต้นฉบับ เช่น Rule ID, phase,
   target, engine, operator, pattern, transform, severity, confidence, action,
   score, pack และ reference
3. การ match Rule เป็นเพียงสัญญาณตรวจจับ ไม่ใช่หลักฐานว่าการโจมตีสำเร็จ
4. แยกให้ชัดระหว่างข้อมูลจาก Rule, ข้อสังเกตจาก event และข้อสรุปที่ยังต้องตรวจยืนยัน
5. ห้ามแต่ง payload, log, IP, user, asset, CVE, ผลกระทบ หรือเหตุการณ์ที่ไม่มีใน
   หลักฐาน
6. ปกปิด credential, token, cookie, session, API key, ข้อมูลส่วนบุคคล และ payload
   ที่อาจใช้โจมตีซ้ำได้
7. อย่าปิด Rule ทั้งกฎจาก false positive เพียงตัวอย่างเดียว ให้จำกัด exception ตาม
   domain, path, method, content type, user, source หรือเงื่อนไขที่แคบที่สุดก่อน

## เครื่องมือหลัก

หา repository root ก่อน:

```bash
REPO_ROOT="$(git rev-parse --show-toplevel)"
RULE_CLI="$REPO_ROOT/skills/security/cherry-rule/scripts/cherry_rule.py"
```

บน Windows PowerShell:

```powershell
$RepoRoot = (git rev-parse --show-toplevel).Trim()
$RuleCli = Join-Path $RepoRoot "skills\security\cherry-rule\scripts\cherry_rule.py"
```

ตรวจความครบถ้วนของ catalog:

```bash
python3 "$RULE_CLI" validate
```

ดูสถิติ:

```bash
python3 "$RULE_CLI" stats
python3 "$RULE_CLI" stats --json
```

ค้นหาด้วย ID, ชื่อ, ภาษาไทย, category, tag, operator หรือคำในคำอธิบาย:

```bash
python3 "$RULE_CLI" search CWAF-GUI-200001
python3 "$RULE_CLI" search "SQL injection"
python3 "$RULE_CLI" search "prompt injection" --category ai --limit 20
python3 "$RULE_CLI" search token --engine token_parser --severity high
python3 "$RULE_CLI" search bot --action challenge --json
```

ดูค่าทางเทคนิคของ Rule:

```bash
python3 "$RULE_CLI" show CWAF-GUI-200001
python3 "$RULE_CLI" show CWAF-GUI-200001 --json
```

สร้างคำอธิบายภาษาไทยแบบละเอียด:

```bash
python3 "$RULE_CLI" explain CWAF-GUI-200001
python3 "$RULE_CLI" explain CWAF-GUI-200001 --json
```

หากระบบใช้คำสั่ง `python` แทน `python3` ให้เปลี่ยนเฉพาะ executable อย่าแก้ไข
catalog

## ขั้นตอนตอบคำถามเกี่ยวกับ Rule

### 1. ระบุ Rule ให้ถูกตัว

หากผู้ใช้ส่ง Rule ID ให้ใช้ `show` หรือ `explain` แบบ exact match ก่อนเสมอ

หากผู้ใช้ส่งเพียงชื่อ เหตุการณ์ หรือคำอธิบาย ให้ใช้ `search` แล้วเลือก Rule จาก
หลักฐานที่ตรงที่สุด อย่าเดา ID จากชื่อคล้ายกัน หากมีหลายตัวให้แสดงตัวเลือกพร้อม
ความแตกต่างที่สำคัญ

### 2. อ่านบริบทของ event แยกจากนิยาม Rule

สำหรับ WAF, API gateway หรือ security event ให้แยกข้อมูลเป็นสองชั้น:

- **นิยาม Rule**: ค่าจาก catalog เช่น target, phase, operator, severity และ action
- **หลักฐาน event**: timestamp, domain, path, method, status, correlation ID,
  matched field, score, policy และ log จากปลายทาง

หาก event ไม่มี matched field หรือค่าที่ทำให้ match ให้ระบุว่าหลักฐานยังไม่พอ
อธิบายได้เพียงหลักการของ Rule ห้ามสร้างตัวอย่าง payload ให้ดูเหมือนเป็นข้อมูลจริง

### 3. ตรวจสถานะภาษา

แต่ละ Rule มี `localization.status`:

- `native`: ชื่อและคำอธิบายไทยมาจาก catalog ต้นฉบับ
- `generated`: ข้อความไทย fallback สร้างจาก field ที่ผ่าน validation ของ Rule
  โดยเก็บข้อความต้นฉบับไว้ใน `source_name_th` และ `source_description_th`

เมื่อสถานะเป็น `generated` ให้บอกสั้น ๆ ว่าเป็นคำอธิบายไทยที่สร้างจากโครงสร้าง
Rule ไม่ใช่คำแปลที่ผู้ดูแล catalog ตรวจทานแล้ว ห้ามทำให้ผู้ใช้นึกว่าเป็นข้อความ
official ที่ผ่าน human review

### 4. อธิบายให้ครบ

คำตอบภาษาไทยต้องมีหัวข้อต่อไปนี้เมื่อผู้ใช้ขอคำอธิบายแบบละเอียด:

```markdown
# <RULE_ID>: <ชื่อภาษาไทย>

## กฎนี้ตรวจอะไร
- จุดประสงค์และประเภทภัยคุกคาม

## ตรวจตรงไหนและเมื่อใด
- phase, targets, engine และ requirements

## หลักการตรวจจับ
- operator, pattern/check/params และ transforms
- อธิบายความหมายโดยไม่แปลง pattern เป็น payload พร้อมโจมตี

## ระดับความเสี่ยงและการตอบสนอง
- severity, confidence, action, score และ default_enabled
- ผลกระทบที่เป็นไปได้โดยแยกจากผลกระทบที่ยืนยันแล้ว

## False positive ที่ต้องระวัง
- สาเหตุ benign ที่เป็นไปได้และข้อมูลที่ควรตรวจเพิ่ม

## วิธีปรับแต่ง Rule
- exception ที่แคบ, monitor ก่อน block และ rollback

## วิธีตรวจยืนยันเหตุการณ์
- request/response ที่ redacted, correlation ID, application log,
  endpoint/network evidence และ asset owner

## แหล่งที่มา
- source pack, version, tags, references และ localization status
```

CLI `explain` สร้างโครงสร้างนี้ให้แล้ว ใช้ผลลัพธ์เป็นแกนคำตอบและเติมเฉพาะบริบท
event ที่ผู้ใช้ให้มา

### 5. ให้ข้อสรุปตามระดับหลักฐาน

ใช้ภาษาตามหลักฐาน:

- พบ pattern: “Rule match” หรือ “พบรูปแบบที่กฎสนใจ”
- มี log ปลายทางรองรับ: “มีหลักฐานสอดคล้องกับความพยายามโจมตี”
- ยืนยันผลกระทบแล้ว: ระบุผลกระทบพร้อมหลักฐานที่ตรวจสอบได้
- หลักฐานไม่พอ: ระบุข้อจำกัดตรง ๆ

ห้ามเปลี่ยน “Rule match” เป็น “ถูกแฮ็กแล้ว” เพราะประโยคหลังฟังตื่นเต้นกว่า
แต่ไม่ได้ทำให้หลักฐานเพิ่มขึ้นแม้แต่นิดเดียว

## การวิเคราะห์หลาย Rule

เมื่อ event มีหลาย Rule:

1. ดึงข้อมูลทุก ID ด้วย `show --json`
2. จัดกลุ่มตาม category, phase, target และ action
3. ตรวจว่าเป็น request เดียวกันจาก correlation ID หรือไม่
4. แยก primary signal ออกจาก secondary score
5. อธิบายผลรวมของ policy โดยไม่บวก score เองหากไม่ทราบ scoring model
6. ระบุ Rule ที่ block จริงและ Rule ที่เพียงเพิ่ม score

อย่าโหลด catalog ทั้ง 512 Rule เข้า model context เมื่อผู้ใช้ถามเพียงไม่กี่ตัว ใช้
`search`, `show` และ `explain` เพื่อดึงเฉพาะข้อมูลที่เกี่ยวข้อง การเผา context
ทั้งหมดเพื่อหา Rule เดียวเป็นพิธีกรรมที่แพงและไร้ประโยชน์

## การใช้ร่วมกับ Cherry PCAP

เมื่อผู้ใช้มีทั้ง WAF event และ PCAP:

1. ใช้ CherryRule อธิบาย logic ของ Rule
2. ใช้ `cherry-pcap` ตรวจ flow, DNS, IP, port, protocol และ timing
3. เชื่อมหลักฐานด้วย timestamp, source/destination และ correlation ที่มีจริง
4. อย่าอ้างว่า packet capture ยืนยัน application-layer exploit หากไม่มี payload
   หรือ server log ที่รองรับ

## แหล่งข้อมูลและความน่าเชื่อถือ

- Catalog runtime: `data/cherry-rules.th.json`
- Provenance แบบอ่านด้วยโปรแกรม: `data/provenance.json`
- รายละเอียดการนำเข้า: `PROVENANCE.md`
- CLI: `scripts/cherry_rule.py`

ใช้ `validate` เมื่อไฟล์ถูกอัปเดต ย้าย หรือเกิดข้อสงสัยเรื่องความครบถ้วน หาก
validation ไม่ผ่าน ให้หยุดอธิบาย Rule จาก catalog นั้นและรายงานข้อผิดพลาดแทนการ
เดาข้อมูลทดแทน
