#!/usr/bin/env bash
# Pilotage du lab IDS : réseaux + VM libvirt (qemu:///system) et stack ELK (Docker).
# Tout est préfixé "ids-" pour ne rien toucher d'autre sur l'hôte.
#
#   ./lab.sh up       vérifie l'hôte, crée ce qui manque puis démarre réseaux, ELK et VM
#   ./lab.sh down     arrête proprement VM et ELK (données conservées)
#   ./lab.sh status   état des réseaux, VM et conteneurs
#   ./lab.sh reset    remet les VM à l'état des images d'origine (efface les overlays)
#   ./lab.sh destroy  supprime VM, réseaux, disques et conteneurs ; garde les volumes Docker
#
# Les images de base (debian13.qcow2, kali.qcow2) sont importées une fois dans le pool
# "ids-lab" et ne sont jamais modifiées : chaque VM écrit dans un overlay qcow2.
set -euo pipefail

export LIBVIRT_DEFAULT_URI=qemu:///system
LAB="$(cd "$(dirname "$0")" && pwd)"
# Emplacement des gros fichiers hors dépôt (images *.qcow2 et stack elk/ : .env, certs, volumes).
# Par défaut le dossier qui contient lab/ ; surchargeable par IDS_HOME, posé dans lab/lab.conf.
[ -f "$LAB/lab.conf" ] && . "$LAB/lab.conf"
ROOT="${IDS_HOME:-$(dirname "$LAB")}"
XML="$LAB/libvirt"
ELK="$ROOT/elk"

POOL=ids-lab
POOL_DIR=/var/lib/libvirt/images/ids-lab
NETS=(ids-nat ids-lab-net)
# VM → image de base (à la racine du projet)
declare -A VMS=([victime]=debian13.qcow2 [kali]=kali.qcow2)

log() { printf '\e[1;34m==\e[0m %s\n' "$*"; }
warn() { printf '\e[1;33mAttention :\e[0m %s\n' "$*" >&2; }
die() { printf '\e[1;31mErreur :\e[0m %s\n' "$*" >&2; exit 1; }

# --- Prérequis de l'hôte ---------------------------------------------------------

check_host() {
  local c
  for c in virsh docker; do
    command -v "$c" >/dev/null || die "commande $c introuvable (voir docs/00-lancer-le-lab.md)"
  done
  docker compose version &>/dev/null || die "plugin Docker Compose v2 absent (commande \"docker compose\")"
  docker info &>/dev/null || die "Docker inaccessible : démon arrêté, ou utilisateur hors du groupe docker"
  virsh uri &>/dev/null || die "libvirt inaccessible : service libvirtd arrêté, ou utilisateur hors du groupe libvirt"
  [ -e /dev/kvm ] || die "/dev/kvm absent : virtualisation (VT-x / AMD-V) désactivée dans le BIOS, ou module kvm non chargé"
  local mmc
  mmc="$(cat /proc/sys/vm/max_map_count)"
  [ "$mmc" -ge 262144 ] || die "vm.max_map_count=$mmc, Elasticsearch exige 262144 :
  echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-elastic.conf && sudo sysctl --system"
  local mem
  mem="$(awk '/^MemTotal/ {print int($2/1024/1024)}' /proc/meminfo)"
  [ "$mem" -ge 15 ] || warn "${mem} Go de RAM : le lab en demande ~12 Go (VM 6 Go + ELK 6 Go), réduire ES_MEM_LIMIT dans elk/.env"
}

# --- Réseaux -------------------------------------------------------------------

# Le réseau "default" de libvirt utilise souvent le même sous-réseau 192.168.122.0/24.
free_subnet() {
  virsh net-info default 2>/dev/null | grep >/dev/null '^Active:.*yes' || return 0
  virsh net-dumpxml default | grep >/dev/null "address='192.168.122.1'" || return 0
  warn "le réseau libvirt \"default\" occupe 192.168.122.0/24, nécessaire au lab"
  read -rp "Le désactiver le temps du lab (les autres VM qui l'utilisent perdront le réseau) ? [o/N] " a
  [ "$a" = o ] || die "abandon ; le relancer plus tard avec : virsh net-start default"
  virsh net-destroy default >/dev/null
}

setup_nets() {
  local n
  for n in "${NETS[@]}"; do
    virsh net-info "$n" &>/dev/null || { log "Définition du réseau $n"; virsh net-define "$XML/$n.xml" >/dev/null; }
  done
  for n in "${NETS[@]}"; do
    virsh net-info "$n" | grep >/dev/null '^Active:.*yes' && continue
    [ "$n" = ids-nat ] && free_subnet
    log "Démarrage du réseau $n"
    virsh net-start "$n" >/dev/null
  done
}

# --- Disques -------------------------------------------------------------------

has_vol() { virsh vol-info --pool "$POOL" "$1" &>/dev/null; }

setup_pool() {
  if ! virsh pool-info "$POOL" &>/dev/null; then
    log "Création du pool $POOL ($POOL_DIR)"
    virsh pool-define-as "$POOL" dir --target "$POOL_DIR" >/dev/null
    virsh pool-build "$POOL" >/dev/null
    virsh pool-autostart "$POOL" >/dev/null
  fi
  virsh pool-info "$POOL" | grep >/dev/null '^State:.*running' || virsh pool-start "$POOL" >/dev/null
}

# Importe l'image de base dans le pool, une seule fois.
ensure_base() {
  local img=$1
  has_vol "$img" && return
  [ -f "$ROOT/$img" ] || die "image $ROOT/$img introuvable"
  log "Import de $img dans le pool $POOL (une seule fois, quelques minutes)"
  virsh vol-create-as "$POOL" "$img" "$(stat -c %s "$ROOT/$img")" --format qcow2 >/dev/null
  virsh vol-upload --pool "$POOL" "$img" "$ROOT/$img"
}

ensure_overlay() {
  local vm=$1 img=${VMS[$1]}
  ensure_base "$img"
  has_vol "$vm.qcow2" && return
  local size
  size="$(virsh vol-info --pool "$POOL" "$img" --bytes | awk '/^Capacity/ {print $2}')"
  log "Création de l'overlay $vm.qcow2 sur $img"
  virsh vol-create-as "$POOL" "$vm.qcow2" "$size" --format qcow2 \
    --backing-vol "$(virsh vol-path --pool "$POOL" "$img")" --backing-vol-format qcow2 >/dev/null
}

# --- VM ------------------------------------------------------------------------

is_running() { virsh domstate "ids-$1" 2>/dev/null | grep >/dev/null running; }

setup_vms() {
  local vm
  setup_pool
  for vm in "${!VMS[@]}"; do
    ensure_overlay "$vm"
    virsh dominfo "ids-$vm" &>/dev/null || { log "Définition de la VM ids-$vm"; virsh define "$XML/ids-$vm.xml" >/dev/null; }
  done
}

start_vms() {
  local vm
  for vm in victime kali; do
    is_running "$vm" || { log "Démarrage de ids-$vm"; virsh start "ids-$vm" >/dev/null; }
  done
}

# La victime doit obtenir son bail DHCP sur ids-nat ; sinon c'est presque toujours le pare-feu de l'hôte.
wait_network() {
  log "Attente de l'adresse réseau de la victime (jusqu'à 2 min)"
  for _ in $(seq 60); do
    virsh net-dhcp-leases ids-nat | grep >/dev/null 192.168.122.206 && { log "Victime joignable en 192.168.122.206"; return; }
    sleep 2
  done
  warn "aucun bail DHCP sur ids-nat : le pare-feu de l'hôte bloque probablement les bridges du lab."
  if systemctl is-active -q ufw 2>/dev/null; then
    cat >&2 <<'EOF'
ufw est actif. Autoriser DHCP/DNS sur les bridges du lab et la sortie NAT de la victime :
  for br in virbr-ids virbr-lab; do
    sudo ufw allow in on $br to any port 67 proto udp
    sudo ufw allow in on $br to any port 53
  done
  sudo ufw route allow in on virbr-ids
Puis, dans la victime et dans Kali : redémarrer, ou  nmcli networking off && nmcli networking on
EOF
  else
    echo "Voir « En cas de problème » dans docs/00-lancer-le-lab.md" >&2
  fi
}

stop_vms() {
  local vm
  for vm in "${!VMS[@]}"; do
    is_running "$vm" || continue
    log "Arrêt de ids-$vm"
    virsh shutdown "ids-$vm" >/dev/null
  done
  for vm in "${!VMS[@]}"; do
    for _ in $(seq 60); do is_running "$vm" || break; sleep 1; done
    if is_running "$vm"; then warn "ids-$vm ne répond pas : arrêt forcé"; virsh destroy "ids-$vm" >/dev/null; fi
  done
}

# --- ELK -----------------------------------------------------------------------

compose() { docker compose --project-directory "$ELK" -f "$ELK/compose.yaml" "$@"; }

# Restaure un volume Docker depuis sa sauvegarde, uniquement s'il n'existe pas.
restore_volume() {
  local vol=ids-elk_$1 archive=$ELK/$1.tgz
  docker volume inspect "$vol" &>/dev/null && return
  [ -f "$archive" ] || die "volume $vol absent et sauvegarde $archive introuvable"
  log "Restauration du volume $vol"
  # Labels Compose : sinon "docker compose up" signale un volume créé hors de Compose
  docker volume create --label com.docker.compose.project=ids-elk \
    --label com.docker.compose.volume="$1" "$vol" >/dev/null
  docker run --rm -v "$vol":/data -v "$ELK":/backup:ro alpine tar xzf "/backup/$1.tgz" -C /data
}

start_elk() {
  # Après le premier lancement, le conteneur setup passe certs/ en root:root 750 :
  # on ne teste que la présence du dossier, toujours visible.
  if [ ! -f "$ELK/.env" ] || [ ! -d "$ELK/certs" ]; then
    log "Extraction de elk-secrets.tgz (.env + certificats)"
    tar xzf "$ELK/elk-secrets.tgz" -C "$ELK"
  fi
  restore_volume esdata01
  restore_volume kibanadata
  log "Démarrage d'Elasticsearch + Kibana (2 à 3 min avant \"healthy\")"
  compose up -d
}

# --- Commandes -----------------------------------------------------------------

cmd_up() {
  check_host
  setup_nets
  setup_vms
  start_elk
  start_vms
  wait_network
  cmd_status
  cat <<EOF

Kibana        : http://localhost:5601  (elastic / ELASTIC_PASSWORD de elk/.env)
Victime       : 192.168.122.206 (NAT) · 10.10.10.10 (lab)
Kali          : 10.10.10.30 (lab uniquement)
Écrans des VM : virt-manager, ou  virt-viewer -c qemu:///system ids-kali
EOF
}

cmd_down() {
  stop_vms
  log "Arrêt d'ELK"
  compose stop
}

cmd_status() {
  echo; virsh net-list --all | grep -E 'Name|ids-' || true
  echo; virsh list --all | grep -E 'Name|ids-' || true
  echo; compose ps --format 'table {{.Name}}\t{{.Status}}\t{{.Ports}}'
}

cmd_reset() {
  local vm
  for vm in "${!VMS[@]}"; do
    is_running "$vm" && die "arrêter d'abord les VM : ./lab.sh down"
  done
  for vm in "${!VMS[@]}"; do
    has_vol "$vm.qcow2" || continue
    log "Suppression de l'overlay $vm.qcow2"
    virsh vol-delete --pool "$POOL" "$vm.qcow2" >/dev/null
  done
  setup_vms
}

cmd_destroy() {
  local vm n a
  read -rp "Supprimer VM, réseaux, disques (images importées comprises) et conteneurs ids-* ? [o/N] " a
  [ "$a" = o ] || exit 0
  for vm in "${!VMS[@]}"; do
    is_running "$vm" && virsh destroy "ids-$vm" >/dev/null
    virsh dominfo "ids-$vm" &>/dev/null && virsh undefine "ids-$vm" >/dev/null
  done
  if virsh pool-info "$POOL" &>/dev/null; then
    virsh pool-start "$POOL" &>/dev/null || true
    for v in $(virsh vol-list --pool "$POOL" | awk 'NR>2 && $1 {print $1}'); do
      virsh vol-delete --pool "$POOL" "$v" >/dev/null
    done
    virsh pool-destroy "$POOL" >/dev/null || true
    virsh pool-delete "$POOL" >/dev/null || true
    virsh pool-undefine "$POOL" >/dev/null
  fi
  for n in "${NETS[@]}"; do
    virsh net-destroy "$n" &>/dev/null || true
    virsh net-undefine "$n" &>/dev/null || true
  done
  compose down
  log "Fait. Volumes Docker ids-elk_* conservés (docker volume rm pour repartir des sauvegardes)."
}

case "${1:-}" in
  up) cmd_up ;;
  down) cmd_down ;;
  status) cmd_status ;;
  reset) cmd_reset ;;
  destroy) cmd_destroy ;;
  *) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
