#!/bin/bash
# ============================================================================
# verify_curl.sh - Vérification universelle du workaround ITP Kameleoon
# Usage: ./verify_curl.sh <URL> [DOMAIN]
#
# Exemples:
#   ./verify_curl.sh https://www.example.com
#   ./verify_curl.sh https://www.example.com/kameleoon-sync example.com
#   ./verify_curl.sh https://www.example.com .example.com
# ============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
BOLD='\033[1m'

URL="${1:-}"
EXPECTED_DOMAIN="${2:-}"

if [ -z "$URL" ]; then
    echo -e "${RED}Usage: $0 <URL> [EXPECTED_DOMAIN]${NC}"
    echo "  URL             : L'URL à tester (page ou endpoint de sync)"
    echo "  EXPECTED_DOMAIN : Le top-level domain attendu (ex: example.com)"
    exit 1
fi

PASS=0
FAIL=0
WARN=0

check() {
    local label="$1"
    local result="$2"  # "pass", "fail", "warn"
    local detail="$3"
    
    case "$result" in
        pass) echo -e "  ${GREEN}✅ PASS${NC} — $label: $detail"; ((PASS++)) ;;
        fail) echo -e "  ${RED}❌ FAIL${NC} — $label: $detail"; ((FAIL++)) ;;
        warn) echo -e "  ${YELLOW}⚠️  WARN${NC} — $label: $detail"; ((WARN++)) ;;
    esac
}

echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  Kameleoon ITP Workaround — Vérification du cookie backend   ${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# ──────────────────────────────────────────────────────────────
# TEST 1 : Requête SANS cookie (première visite)
# ──────────────────────────────────────────────────────────────
echo -e "${BLUE}▶ Test 1 : Première visite (sans cookie existant)${NC}"
echo "  → GET $URL"
echo ""

HEADERS=$(curl -sS -D - -o /dev/null "$URL" 2>&1)
HTTP_CODE=$(echo "$HEADERS" | grep -i "^HTTP/" | tail -1 | awk '{print $2}')

# Chercher le header Set-Cookie pour kameleoonVisitorCode
SET_COOKIE_LINE=$(echo "$HEADERS" | grep -i "^Set-Cookie:.*kameleoonVisitorCode" | head -1 || true)

if [ -z "$SET_COOKIE_LINE" ]; then
    check "Cookie Set-Cookie présent" "fail" "Aucun header Set-Cookie pour kameleoonVisitorCode trouvé"
    echo ""
    echo -e "${RED}⛔ Le cookie n'est pas set par le serveur. L'implémentation ITP est absente ou cassée.${NC}"
    echo ""
    echo "Headers reçus :"
    echo "$HEADERS" | grep -i "set-cookie" || echo "  (aucun Set-Cookie trouvé)"
    exit 1
fi

check "Header Set-Cookie présent" "pass" "kameleoonVisitorCode trouvé dans la réponse"

# Extraire la valeur du visitorCode
VISITOR_CODE=$(echo "$SET_COOKIE_LINE" | sed -n 's/.*kameleoonVisitorCode=\([^;]*\).*/\1/p' | tr -d '[:space:]')

# Vérifier le format (16 caractères, a-z0-9)
if [[ "$VISITOR_CODE" =~ ^[a-z0-9]{16}$ ]]; then
    check "Format visitorCode" "pass" "'$VISITOR_CODE' (16 chars, [a-z0-9])"
elif [[ ${#VISITOR_CODE} -eq 16 ]]; then
    check "Format visitorCode" "warn" "'$VISITOR_CODE' — 16 chars mais contient des caractères hors [a-z0-9] (custom visitor code ?)"
elif [ -n "$VISITOR_CODE" ]; then
    check "Format visitorCode" "warn" "'$VISITOR_CODE' — longueur ${#VISITOR_CODE} ≠ 16 (custom visitor code ?)"
else
    check "Format visitorCode" "fail" "Valeur du cookie vide"
fi

# Vérifier le Domain
COOKIE_DOMAIN=$(echo "$SET_COOKIE_LINE" | grep -oi 'domain=[^;]*' | head -1 | cut -d= -f2 | tr -d '[:space:]')
if [ -n "$EXPECTED_DOMAIN" ]; then
    # Normaliser (ignorer le point initial)
    NORM_COOKIE=$(echo "$COOKIE_DOMAIN" | sed 's/^\.//')
    NORM_EXPECTED=$(echo "$EXPECTED_DOMAIN" | sed 's/^\.//')
    if [ "$NORM_COOKIE" = "$NORM_EXPECTED" ]; then
        check "Domain" "pass" "'$COOKIE_DOMAIN' (attendu: $EXPECTED_DOMAIN)"
    else
        check "Domain" "fail" "'$COOKIE_DOMAIN' (attendu: $EXPECTED_DOMAIN)"
    fi
elif [ -n "$COOKIE_DOMAIN" ]; then
    check "Domain" "warn" "'$COOKIE_DOMAIN' — pas de domaine attendu fourni, vérifie manuellement"
else
    check "Domain" "warn" "Attribut Domain absent du Set-Cookie (le navigateur utilisera le domaine de la requête)"
fi

# Vérifier le Path
COOKIE_PATH=$(echo "$SET_COOKIE_LINE" | grep -oi 'path=[^;]*' | head -1 | cut -d= -f2 | tr -d '[:space:]')
if [ "$COOKIE_PATH" = "/" ]; then
    check "Path" "pass" "'/'"
elif [ -n "$COOKIE_PATH" ]; then
    check "Path" "fail" "'$COOKIE_PATH' (attendu: '/')"
else
    check "Path" "warn" "Attribut Path absent (par défaut le navigateur utilisera le path de la requête)"
fi

# Vérifier HttpOnly (doit être ABSENT pour que le JS frontend puisse lire le cookie)
if echo "$SET_COOKIE_LINE" | grep -qi "httponly"; then
    check "HttpOnly" "fail" "HttpOnly est présent ! Le cookie DOIT être accessible en JS frontend."
else
    check "HttpOnly" "pass" "HttpOnly absent (le cookie est lisible par le JS Kameleoon)"
fi

# Vérifier l'expiration
MAX_AGE=$(echo "$SET_COOKIE_LINE" | grep -oi 'max-age=[^;]*' | head -1 | cut -d= -f2 | tr -d '[:space:]')
EXPIRES=$(echo "$SET_COOKIE_LINE" | grep -oi 'expires=[^;]*' | head -1 | sed 's/^expires=//i' | tr -d '[:space:]')

if [ -n "$MAX_AGE" ]; then
    # Attendu : ~32832000 secondes (380 jours)
    if [ "$MAX_AGE" -ge 31000000 ] && [ "$MAX_AGE" -le 33000000 ]; then
        DAYS=$((MAX_AGE / 86400))
        check "Expiration (Max-Age)" "pass" "${MAX_AGE}s (~${DAYS} jours)"
    elif [ "$MAX_AGE" -gt 0 ]; then
        DAYS=$((MAX_AGE / 86400))
        check "Expiration (Max-Age)" "warn" "${MAX_AGE}s (~${DAYS} jours) — attendu ~32832000s (~380 jours)"
    else
        check "Expiration (Max-Age)" "fail" "${MAX_AGE}s — le cookie va expirer immédiatement ou très vite"
    fi
elif [ -n "$EXPIRES" ]; then
    check "Expiration (Expires)" "warn" "'$EXPIRES' — vérifie manuellement que c'est ~380 jours dans le futur"
else
    check "Expiration" "fail" "Ni Max-Age ni Expires présent — le cookie sera un session cookie !"
fi

# Vérifier Secure flag si HTTPS
if echo "$URL" | grep -qi "^https"; then
    if echo "$SET_COOKIE_LINE" | grep -qi "secure"; then
        check "Secure (HTTPS)" "pass" "Flag Secure présent (recommandé pour HTTPS)"
    else
        check "Secure (HTTPS)" "warn" "Flag Secure absent — recommandé pour les sites en HTTPS"
    fi
fi

echo ""

# ──────────────────────────────────────────────────────────────
# TEST 2 : Requête AVEC cookie existant (visite retour)
# ──────────────────────────────────────────────────────────────
echo -e "${BLUE}▶ Test 2 : Visite retour (avec cookie existant)${NC}"
echo "  → GET $URL avec Cookie: kameleoonVisitorCode=$VISITOR_CODE"
echo ""

HEADERS2=$(curl -sS -D - -o /dev/null -H "Cookie: kameleoonVisitorCode=$VISITOR_CODE" "$URL" 2>&1)
SET_COOKIE_LINE2=$(echo "$HEADERS2" | grep -i "^Set-Cookie:.*kameleoonVisitorCode" | head -1 || true)

if [ -n "$SET_COOKIE_LINE2" ]; then
    VISITOR_CODE2=$(echo "$SET_COOKIE_LINE2" | sed -n 's/.*kameleoonVisitorCode=\([^;]*\).*/\1/p' | tr -d '[:space:]')
    if [ "$VISITOR_CODE2" = "$VISITOR_CODE" ]; then
        check "Reprise du visitorCode" "pass" "Le serveur renvoie le même code '$VISITOR_CODE2'"
    else
        check "Reprise du visitorCode" "fail" "Le serveur a généré un NOUVEAU code '$VISITOR_CODE2' au lieu de reprendre '$VISITOR_CODE'"
    fi
else
    check "Reprise du visitorCode" "warn" "Pas de Set-Cookie en retour — OK si le cookie est set uniquement à la création"
fi

echo ""

# ──────────────────────────────────────────────────────────────
# TEST 3 : Requête avec un custom visitorCode
# ──────────────────────────────────────────────────────────────
CUSTOM_CODE="testcodeabcd1234"
echo -e "${BLUE}▶ Test 3 : Envoi d'un custom visitorCode${NC}"
echo "  → GET $URL avec Cookie: kameleoonVisitorCode=$CUSTOM_CODE"
echo ""

HEADERS3=$(curl -sS -D - -o /dev/null -H "Cookie: kameleoonVisitorCode=$CUSTOM_CODE" "$URL" 2>&1)
SET_COOKIE_LINE3=$(echo "$HEADERS3" | grep -i "^Set-Cookie:.*kameleoonVisitorCode" | head -1 || true)

if [ -n "$SET_COOKIE_LINE3" ]; then
    VISITOR_CODE3=$(echo "$SET_COOKIE_LINE3" | sed -n 's/.*kameleoonVisitorCode=\([^;]*\).*/\1/p' | tr -d '[:space:]')
    if [ "$VISITOR_CODE3" = "$CUSTOM_CODE" ]; then
        check "Préservation custom code" "pass" "Le serveur préserve le code custom '$CUSTOM_CODE'"
    else
        check "Préservation custom code" "fail" "Le serveur a écrasé '$CUSTOM_CODE' par '$VISITOR_CODE3'"
    fi
else
    check "Préservation custom code" "warn" "Pas de Set-Cookie — vérifier si c'est attendu"
fi

echo ""

# ──────────────────────────────────────────────────────────────
# RÉSUMÉ
# ──────────────────────────────────────────────────────────────
echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  RÉSUMÉ${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${GREEN}✅ PASS : $PASS${NC}"
echo -e "  ${YELLOW}⚠️  WARN : $WARN${NC}"
echo -e "  ${RED}❌ FAIL : $FAIL${NC}"
echo ""

if [ "$FAIL" -eq 0 ] && [ "$WARN" -eq 0 ]; then
    echo -e "  ${GREEN}${BOLD}🎉 Implémentation ITP parfaite !${NC}"
elif [ "$FAIL" -eq 0 ]; then
    echo -e "  ${YELLOW}${BOLD}⚠️ Implémentation OK mais quelques points à vérifier manuellement.${NC}"
else
    echo -e "  ${RED}${BOLD}⛔ Implémentation incorrecte — $FAIL erreur(s) détectée(s).${NC}"
fi

echo ""
echo "Header Set-Cookie complet :"
echo "  $SET_COOKIE_LINE"
echo ""
