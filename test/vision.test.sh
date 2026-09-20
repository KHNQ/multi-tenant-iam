#!/bin/bash
# test-vision.sh
# Run with: chmod +x test-vision.sh && ./test-vision.sh

BASE_URL="http://127.0.0.1:8081"
PASS=0
FAIL=0

# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

green='\033[0;32m'
red='\033[0;31m'
nc='\033[0m'

pass() {
  echo -e "${green}  PASS${nc} $1"
  ((PASS++))
}

fail() {
  echo -e "${red}  FAIL${nc} $1"
  ((FAIL++))
}

check_status() {
  local test_name=$1
  local expected=$2
  local actual=$3

  if [ "$actual" -eq "$expected" ]; then
    pass "$test_name - status $actual"
  else
    fail "$test_name - expected status $expected, got $actual"
  fi
}

check_field() {
  local test_name=$1
  local expected=$2
  local actual=$3

  if [ "$actual" = "$expected" ]; then
    pass "$test_name"
  else
    fail "$test_name - expected '$expected', got '$actual'"
  fi
}

# ─────────────────────────────────────────────
# GET /catalog
# ─────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " Testing GET /catalog"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

CATALOG_STATUS=$(curl -s -o /dev/null -w "%{http_code}" $BASE_URL/catalog)
CATALOG_BODY=$(curl -s $BASE_URL/catalog)

check_status "GET /catalog" 200 "$CATALOG_STATUS"
check_field  "catalog.name"    "vision"                  "$(echo $CATALOG_BODY | grep -o '"name":"[^"]*"'    | cut -d: -f2 | tr -d '"')"
check_field  "catalog.version" "v1.5"                    "$(echo $CATALOG_BODY | grep -o '"version":"[^"]*"' | cut -d: -f2 | tr -d '"')"
check_field  "catalog.owner"   "cv_team"                 "$(echo $CATALOG_BODY | grep -o '"owner":"[^"]*"'   | cut -d: -f2 | tr -d '"')"
check_field  "catalog.baseUrl" "http://localhost:8081"   "$(echo $CATALOG_BODY | grep -o '"baseUrl":"[^"]*"' | cut -d: -f2- | tr -d '"')"

# Check all 3 endpoints are listed
for endpoint in "/vision/service1" "/vision/service2" "/vision/service3"; do
  if echo "$CATALOG_BODY" | grep -q "$endpoint"; then
    pass "catalog.endpoints contains $endpoint"
  else
    fail "catalog.endpoints missing $endpoint"
  fi
done

# ─────────────────────────────────────────────
# GET /vision/service1
# ─────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " Testing GET /vision/service1"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

S1_STATUS=$(curl -s -o /dev/null -w "%{http_code}" $BASE_URL/vision/service1)
S1_BODY=$(curl -s $BASE_URL/vision/service1)

check_status "GET /vision/service1" 200 "$S1_STATUS"
check_field  "service1.source" "Vision Service 1" "$(echo $S1_BODY | grep -o '"source":"[^"]*"' | cut -d: -f2 | tr -d '"')"
check_field  "service1.type"   "object_detection" "$(echo $S1_BODY | grep -o '"type":"[^"]*"'   | cut -d: -f2 | tr -d '"')"

# ─────────────────────────────────────────────
# GET /vision/service2
# ─────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " Testing GET /vision/service2"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

S2_STATUS=$(curl -s -o /dev/null -w "%{http_code}" $BASE_URL/vision/service2)
S2_BODY=$(curl -s $BASE_URL/vision/service2)

check_status "GET /vision/service2" 200 "$S2_STATUS"
check_field  "service2.source" "Vision Service 2" "$(echo $S2_BODY | grep -o '"source":"[^"]*"' | cut -d: -f2 | tr -d '"')"
check_field  "service2.type"   "ocr"              "$(echo $S2_BODY | grep -o '"type":"[^"]*"'   | cut -d: -f2 | tr -d '"')"

# ─────────────────────────────────────────────
# GET /vision/service3
# ─────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " Testing GET /vision/service3"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

S3_STATUS=$(curl -s -o /dev/null -w "%{http_code}" $BASE_URL/vision/service3)
S3_BODY=$(curl -s $BASE_URL/vision/service3)

check_status "GET /vision/service3" 200 "$S3_STATUS"
check_field  "service3.source" "Vision Service 3"    "$(echo $S3_BODY | grep -o '"source":"[^"]*"' | cut -d: -f2 | tr -d '"')"
check_field  "service3.type"   "facial_recognition"  "$(echo $S3_BODY | grep -o '"type":"[^"]*"'   | cut -d: -f2 | tr -d '"')"

# ─────────────────────────────────────────────
# Unknown Routes -> expect 404
# ─────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " Testing Unknown Routes"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

UNKNOWN_STATUS=$(curl -s -o /dev/null -w "%{http_code}" $BASE_URL/vision/service99)
check_status "GET /vision/service99" 404 "$UNKNOWN_STATUS"

UNKNOWN_STATUS2=$(curl -s -o /dev/null -w "%{http_code}" $BASE_URL/unknown)
check_status "GET /unknown" 404 "$UNKNOWN_STATUS2"

# ─────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e " Results: ${green}$PASS passed${nc} / ${red}$FAIL failed${nc}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Exit with failure code if any tests failed
[ $FAIL -eq 0 ] || exit 1
