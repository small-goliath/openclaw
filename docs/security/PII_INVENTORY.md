# PII (개인식별정보) 인벤토리

## 개요

이 문서는 OpenClaw 애플리케이션에서 처리하는 모든 PII(개인식별정보) 필드의 포괄적인 인벤토리입니다.
GDPR 및 SOC 2 규정 준수를 위해 작성되었습니다.

## PII 분류 체계

| 레벨         | 설명                  | 예시                                    |
| ------------ | --------------------- | --------------------------------------- |
| **Critical** | 민감한 개인정보       | 비밀번호, 토큰, API 키, 생체인식 데이터 |
| **High**     | 직접 식별 가능한 정보 | 이메일, 전화번호, 실명, 주소            |
| **Medium**   | 간접 식별 가능한 정보 | 사용자명, IP 주소, 위치 데이터          |
| **Low**      | 낮은 식별 가능성      | 브라우저 정보, OS 정보                  |

## PII 필드 목록

### 1. 사용자 인증 정보

| 필드명         | 타입   | 분류     | 위치                     | 저장         | 암호화 | 설명                   |
| -------------- | ------ | -------- | ------------------------ | ------------ | ------ | ---------------------- |
| `password`     | string | Critical | `auth.ts`                | DB           | Yes    | 사용자 비밀번호 (해시) |
| `token`        | string | Critical | `storage.ts`             | Cookie       | Yes    | JWT 액세스 토큰        |
| `refreshToken` | string | Critical | `auth-cookie.ts`         | Cookie       | Yes    | JWT 리프레시 토큰      |
| `apiKey`       | string | Critical | `auth-profiles/store.ts` | DB           | Yes    | 외부 API 키            |
| `sessionKey`   | string | Medium   | `storage.ts`             | LocalStorage | No     | 세션 식별자            |

### 2. 사용자 프로필 정보

| 필드명           | 타입   | 분류   | 위치      | 저장 | 암호화 | 설명               |
| ---------------- | ------ | ------ | --------- | ---- | ------ | ------------------ |
| `email`          | string | High   | `auth.ts` | DB   | No     | 사용자 이메일 주소 |
| `userName`       | string | Medium | `auth.ts` | DB   | No     | 사용자 표시 이름   |
| `profilePic`     | string | Medium | `auth.ts` | DB   | No     | 프로필 사진 URL    |
| `tailscaleLogin` | string | Medium | `auth.ts` | DB   | No     | Tailscale 로그인   |

### 3. 메시지 및 채팅 데이터

| 필드명           | 타입   | 분류   | 위치               | 저장 | 암호화 | 설명             |
| ---------------- | ------ | ------ | ------------------ | ---- | ------ | ---------------- |
| `messageContent` | string | High   | `memory/schema.ts` | DB   | Yes\*  | 채팅 메시지 내용 |
| `senderId`       | string | Medium | `memory/schema.ts` | DB   | No     | 발신자 식별자    |
| `channelId`      | string | Medium | `memory/schema.ts` | DB   | No     | 채널 식별자      |

### 4. 세션 및 활동 로그

| 필드명        | 타입   | 분류   | 위치                   | 저장 | 암호화 | 설명             |
| ------------- | ------ | ------ | ---------------------- | ---- | ------ | ---------------- |
| `sessionId`   | string | Medium | `sessions/metadata.ts` | DB   | No     | 세션 식별자      |
| `ipAddress`   | string | Medium | `gateway/auth.ts`      | Log  | No     | 클라이언트 IP    |
| `userAgent`   | string | Low    | `gateway/auth.ts`      | Log  | No     | 브라우저 정보    |
| `activityLog` | object | Medium | `audit.ts`             | DB   | Yes    | 사용자 활동 로그 |

### 5. 통합 및 외부 서비스

| 필드명        | 타입   | 분류     | 위치                     | 저장 | 암호화 | 설명                  |
| ------------- | ------ | -------- | ------------------------ | ---- | ------ | --------------------- |
| `credentials` | object | Critical | `auth-profiles/store.ts` | DB   | Yes    | 외부 서비스 인증 정보 |
| `webhookUrl`  | string | High     | `channels/*.ts`          | DB   | Yes    | 웹훅 URL              |
| `botToken`    | string | Critical | `channels/*.ts`          | DB   | Yes    | 봇 토큰               |

### 6. MFA 및 보안

| 필드명               | 타입     | 분류     | 위치             | 저장 | 암호화     | 설명               |
| -------------------- | -------- | -------- | ---------------- | ---- | ---------- | ------------------ |
| `totpSecret`         | string   | Critical | `gateway/mfa.ts` | DB   | Yes        | TOTP 비밀 키       |
| `webauthnCredential` | object   | Critical | `gateway/mfa.ts` | DB   | Yes        | WebAuthn 인증 정보 |
| `backupCodes`        | string[] | Critical | `gateway/mfa.ts` | DB   | Yes (Hash) | MFA 백업 코드      |

## 데이터 흐름 다이어그램

```
┌─────────────────────────────────────────────────────────────────┐
│                         클라이언트                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │   Browser   │  │  Mobile App │  │   Desktop   │             │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘             │
└─────────┼────────────────┼────────────────┼─────────────────────┘
          │                │                │
          └────────────────┴────────────────┘
                           │
                    ┌──────▼──────┐
                    │   Gateway   │
                    │   (auth)    │
                    └──────┬──────┘
                           │
          ┌────────────────┼────────────────┐
          │                │                │
    ┌─────▼─────┐   ┌─────▼─────┐   ┌─────▼─────┐
    │   User    │   │  Session  │   │   Audit   │
    │   Store   │   │   Store   │   │    Log    │
    └───────────┘   └───────────┘   └───────────┘
          │                │                │
          └────────────────┴────────────────┘
                           │
                    ┌──────▼──────┐
                    │   Memory    │
                    │   (SQLite)  │
                    └─────────────┘
```

## 데이터 보존 정책

| 데이터 유형 | 보존 기간      | 삭제 방법 |
| ----------- | -------------- | --------- |
| 인증 로그   | 1년            | 자동 삭제 |
| 활동 로그   | 2년            | 자동 삭제 |
| 채팅 메시지 | 사용자 요청 시 | 수동 삭제 |
| 세션 데이터 | 30일           | 자동 만료 |
| 백업 코드   | 사용 후 즉시   | 자동 삭제 |

## 암호화 적용 현황

### 암호화된 필드

- ✅ 비밀번호 (bcrypt)
- ✅ API 키 (AES-256-GCM)
- ✅ 토큰 (AES-256-GCM)
- ✅ TOTP 비밀 (AES-256-GCM)
- ✅ WebAuthn 인증 정보 (AES-256-GCM)
- ✅ 백업 코드 (SHA-256 Hash)

### 암호화되지 않은 필드

- 이메일 주소 (식별용)
- 사용자명 (식별용)
- 세션 ID (임시 데이터)
- IP 주소 (로그용)

## GDPR 준수 조치

1. **데이터 최소화**: 필요한 최소한의 PII만 수집
2. **목적 제한**: 수집 목적에만 데이터 사용
3. **정확성**: 사용자가 자신의 데이터 수정 가능
4. **저장 제한**: 정책에 따른 자동 삭제
5. **무결성 및 기밀성**: 암호화 및 접근 제어
6. **책임**: 감사 로그 및 DSR 추적

## DSR 처리 절차

### 접근 요청 (Access)

1. 사용자 신원 확인
2. 모든 PII 데이터 수집
3. 데이터 포맷팅 (JSON/PDF)
4. 30일 이내 제공

### 삭제 요청 (Deletion)

1. 사용자 신원 확인
2. 모든 PII 데이터 식별
3. 데이터 삭제 또는 익명화
4. 삭제 확인 제공

### 이식성 요청 (Portability)

1. 사용자 신원 확인
2. 구조화된 데이터 추출
3. 표준 포맷으로 변환
4. 30일 이내 제공

## 감사 및 모니터링

- PII 접근 로그 기록
- 비정상적 접근 패턴 감지
- 월간 PII 인벤토리 검토
- 연간 GDPR 준수 감사

## 업데이트 이력

| 날짜       | 버전 | 변경사항  | 작성자                 |
| ---------- | ---- | --------- | ---------------------- |
| 2026-02-21 | 1.0  | 초기 작성 | OpenClaw Security Team |
