# vulnerabilities

## Description

<details>
<summary><strong>Table Definition</strong></summary>

```sql
CREATE TABLE vulnerabilities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        vulnerability_id TEXT NOT NULL,
        value TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
```

</details>

## Columns

| Name | Type | Default | Nullable | Children | Parents | Comment |
| ---- | ---- | ------- | -------- | -------- | ------- | ------- |
| id | INTEGER |  | true |  |  |  |
| vulnerability_id | TEXT |  | false |  |  | Vulnerability ID |
| value | TEXT |  | false |  |  | Vulnerability data |
| created_at | TIMESTAMP | CURRENT_TIMESTAMP | true |  |  |  |

## Constraints

| Name | Type | Definition |
| ---- | ---- | ---------- |
| id | PRIMARY KEY | PRIMARY KEY (id) |

## Indexes

| Name | Definition |
| ---- | ---------- |
| v_vulnerability_id_idx | CREATE INDEX v_vulnerability_id_idx ON vulnerabilities(vulnerability_id) |

## Relations

![er](vulnerabilities.svg)

---

> Generated by [tbls](https://github.com/k1LoW/tbls)