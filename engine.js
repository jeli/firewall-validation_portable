/*
    Firewall-Validation Portable - Pruef-Engine
    Copyright (C) 2026 Christian Jelitte <christian.jelitte@gmx-topmail.de>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

    Additional term under section 7(b) of the GNU GPL version 3:
    the author attribution must be preserved in every copy and every
    modified version, see the file NOTICE.
*/
/*
  engine.js - Logik-Schicht (kein DOM-Rendering, keine Anzeige).
  Wird per <script src="engine.js"> von index.html und rules-editor.html geladen.

  Oeffentliche Schnittstelle:
    auditXml(xmlText, catalog)  -> {platform, hostname, summary, results}   (results sortiert)
    runAudit(cfg, catalog)      -> ungescorte Einzelergebnisse
    scoreResults(results, catalog), sortResults(results)
    Config                      -> normalisiertes Modell einer config.xml
*/
"use strict";
var DEFAULTS={wan_interfaces:["wan"],sensitive_ports:[22,23,135,139,445,1433,3306,3389,5432,5900,5901,6379,9200,11211,27017],default_communities:["public","private"],wan_zone_severity:"high",penalty:{FAIL:1.0,WARN:0.5,PASS:0.0}};
var WAN_ZONE=new Set(DEFAULTS.wan_interfaces);
var _FALSE_TOKENS=new Set(["0","no","false","disabled","off"]);
var SENSITIVE_PORTS=new Set(DEFAULTS.sensitive_ports);
var SNMP_DEFAULT_COMMUNITIES=new Set(DEFAULTS.default_communities);
var FW_ANY_WAN_SEVERITY=DEFAULTS.wan_zone_severity;
var SEV_ORDER={critical:4,high:3,medium:2,low:1,info:0};
var PENALTY_FACTOR=Object.assign({},DEFAULTS.penalty);
var NON_SCORED=new Set(["NA","MANUAL"]);

function findEl(r,p){if(!r)return null;var ps=p.split("/"),el=r;for(var i=0;i<ps.length;i++){if(!el)return null;el=Array.from(el.children).find(function(c){return c.tagName===ps[i];});}return el||null;}
function findText(r,p,d){var el=findEl(r,p);if(!el||el.textContent==null)return d||"";return(el.textContent||"").trim();}
function findAll(r,t){if(!r)return[];return Array.from(r.children).filter(function(c){return c.tagName===t;});}
function iterAll(r,t){if(!r)return[];return Array.from(r.querySelectorAll(t));}
function elText(e){return(e&&e.textContent!=null)?(e.textContent||"").trim():"";}
function isEnabled(parent,tag){if(!parent)return false;var el=findEl(parent,tag);if(!el)return false;var t=elText(el).toLowerCase();if(t==="")return true;if(_FALSE_TOKENS.has(t))return false;return true;}

function Config(root){this.root=root;this.platform=this._dp(root);this.nested=findEl(root,"OPNsense");this._aliases=this._pa();this._ifaceIPs=this._cip();}
Config.prototype._dp=function(r){var t=(r.tagName||"").toLowerCase();if(t==="pfsense")return"pfsense";if(t==="opnsense")return"opnsense";return"unknown";};
Object.defineProperty(Config.prototype,"isPfsense",{get:function(){return this.platform==="pfsense";}});
Config.prototype.text=function(p,d){return findText(this.root,p,d||"");};
Config.prototype.nestedFind=function(p){return this.nested?findEl(this.nested,p):null;};
Config.prototype._pa=function(){var out={};if(this.isPfsense){var a=findEl(this.root,"aliases");if(!a)return out;for(var i=0;i<a.children.length;i++){var x=a.children[i];if(x.tagName!=="alias")continue;var nm=findText(x,"name","");var ad=findText(x,"address","");out[nm]={type:findText(x,"type",""),content:ad.split(/\s+/).filter(function(t){return t.trim();})};}return out;}if(!this.nested)return out;var a=this.nestedFind("Firewall/Alias/aliases");if(!a)return out;for(var i=0;i<a.children.length;i++){var x=a.children[i];if(x.tagName!=="alias")continue;var nm=findText(x,"name","");var ct=findText(x,"content","").replace(/\n/g,",");out[nm]={type:findText(x,"type",""),content:ct.split(",").map(function(t){return t.trim();}).filter(function(t){return t;})};}return out;};
Object.defineProperty(Config.prototype,"aliases",{get:function(){return this._aliases;}});
Config.prototype.resolveAlias=function(name,seen){seen=seen||new Set();if(seen.has(name))return[];seen.add(name);if(!(name in this._aliases))return[name];var r=[];var self=this;this._aliases[name].content.forEach(function(tok){if(tok in self._aliases)r=r.concat(self.resolveAlias(tok,seen));else r.push(tok);});return r;};
Config.prototype.resolvePorts=function(spec){var out=new Set();if(!spec)return out;var self=this;this.resolveAlias(spec).forEach(function(tok){out.add(String(tok));});return out;};
Config.prototype._cip=function(){var ips=new Set();var ifs=findEl(this.root,"interfaces");if(!ifs)return ips;for(var i=0;i<ifs.children.length;i++){var c=ifs.children[i];var ip=findText(c,"ipaddr","");if(ip&&ip!=="dhcp"&&ip!=="dhcp6"&&ip!=="")ips.add(ip);}return ips;};
Config.prototype.interfaces=function(){var ifs=findEl(this.root,"interfaces");var out={};if(!ifs)return out;for(var i=0;i<ifs.children.length;i++)out[ifs.children[i].tagName]=ifs.children[i];return out;};
Config.prototype.isWanZone=function(iface){return WAN_ZONE.has(iface);};
Config.prototype.webguiPort=function(){var p=this.text("system/webgui/port","");if(p)return p;var pr=this.text("system/webgui/protocol","https").toLowerCase();return pr==="http"?"80":"443";};
Config.prototype.sshElement=function(){return findEl(this.root,"system/ssh");};
Config.prototype.sshEnabled=function(){var s=this.sshElement();if(isEnabled(s,"enabled")||isEnabled(s,"enable"))return true;return isEnabled(findEl(this.root,"system"),"enablesshd");};
Config.parseEndpoint=function(el){var ep={any:false,invert:false,addresses:[],network_kw:null,port:null};if(!el){ep.any=true;return ep;}if(findEl(el,"any"))ep.any=true;var ne=findEl(el,"not");if(ne){var t=elText(ne).toLowerCase();ep.invert=!_FALSE_TOKENS.has(t);}var ad=findText(el,"address");if(ad)ep.addresses.push(ad.trim());var nt=findText(el,"network");if(nt)ep.network_kw=nt.trim();var pt=findText(el,"port");if(pt)ep.port=pt.trim();if(!ep.addresses.length&&!ep.network_kw&&!ep.any)ep.any=true;return ep;};
Config.prototype.isSelfDestination=function(ep){if(ep.network_kw&&(ep.network_kw==="(self)"||ep.network_kw.endsWith("ip")))return true;var self=this;for(var i=0;i<ep.addresses.length;i++){var toks=this.resolveAlias(ep.addresses[i]);for(var j=0;j<toks.length;j++){if(this._ifaceIPs.has(toks[j]))return true;}}return false;};
Config.prototype.filterRules=function(){var flt=findEl(this.root,"filter");var rules=[];if(!flt)return rules;var idx=0;var self=this;for(var i=0;i<flt.children.length;i++){var ru=flt.children[i];if(ru.tagName!=="rule")continue;rules.push({idx:idx++,type:findText(ru,"type",""),interface:findText(ru,"interface",""),direction:findText(ru,"direction",""),protocol:findText(ru,"protocol","any")||"any",source:Config.parseEndpoint(findEl(ru,"source")),destination:Config.parseEndpoint(findEl(ru,"destination")),disabled:findText(ru,"disabled","0")==="1",quick:findText(ru,"quick","0")==="1",log:findText(ru,"log","0")==="1",descr:findText(ru,"descr","").trim(),_el:ru});}return rules;};
Config.prototype.natPortForwards=function(){var nat=findEl(this.root,"nat");var out=[];if(!nat)return out;for(var i=0;i<nat.children.length;i++){var ru=nat.children[i];if(ru.tagName!=="rule")continue;var dst=findEl(ru,"destination");out.push({interface:findText(ru,"interface",""),source:Config.parseEndpoint(findEl(ru,"source")),destPort:dst?findText(dst,"port")||null:null,target:findText(ru,"target",""),localPort:findText(ru,"local-port",""),descr:findText(ru,"descr","").trim()});}return out;};
Config.prototype.users=function(){var s=findEl(this.root,"system");return s?findAll(s,"user"):[];};
Config.prototype.adminGroupMembers=function(){var m=new Set();var s=findEl(this.root,"system");if(!s)return m;var gs=findAll(s,"group");for(var i=0;i<gs.length;i++){var pv=findAll(gs[i],"priv").map(function(p){return elText(p);});if(pv.some(function(p){return p.indexOf("page-all")>=0;})){var mm=findText(gs[i],"member","");mm.split(",").forEach(function(x){if(x.trim())m.add(x.trim());});}}return m;};

function _hostWithSubnetMask(token){if(token.indexOf("/")<0)return false;try{var parts=token.split("/",2);var ipStr=parts[0],pfStr=parts[1];var ps=ipStr.split(".").map(Number);if(ps.length!==4||ps.some(function(p){return p<0||p>255||isNaN(p);}))return false;var pf=parseInt(pfStr,10);if(isNaN(pf)||pf<=0||pf>=32)return false;var ipInt=(ps[0]<<24)|(ps[1]<<16)|(ps[2]<<8)|ps[3];var mask=pf===0?0:((0xFFFFFFFF<<(32-pf))>>>0);var net=(ipInt&mask)>>>0;return ipInt!==net;}catch(e){return false;}}
function _portsInSet(portspec,cfg,sSet){var hit=new Set();var toks=cfg.resolvePorts(portspec);toks.forEach(function(tok){var t=tok.trim();if(/^\d+$/.test(t)){var p=parseInt(t,10);if(sSet.has(p))hit.add(p);}else if(t.indexOf("-")>=0){try{var parts=t.split("-",2);var lo=parseInt(parts[0].trim(),10),hi=parseInt(parts[1].trim(),10);sSet.forEach(function(p){if(p>=lo&&p<=hi)hit.add(p);});}catch(e){}}});return hit;}
function _pfsenseIds(cfg){var ip=findEl(cfg.root,"installedpackages");if(!ip)return{pkgname:null,items:[]};for(var j=0;j<["suricata","snort"].length;j++){var pn=["suricata","snort"][j];var pkg=findEl(ip,pn);if(pkg){var items=[];(function walk(el){if(el!==pkg&&findEl(el,"interface"))items.push(el);for(var i=0;i<el.children.length;i++)walk(el.children[i]);})(pkg);return{pkgname:pn,items:items};}}return{pkgname:null,items:[]};}
function epStr(ep){var b;if(ep.any&&!ep.addresses.length&&!ep.network_kw)b="any";else{var ps=ep.addresses.slice();if(ep.network_kw)ps.push(ep.network_kw);b=ps.join(",")||"any";}if(ep.invert)b="!"+b;return b+(ep.port?":"+ep.port:"");}

var CHECKS={};
function check(id,fn){CHECKS[id]=fn;}
// Bausteine: Pruefungen in Programmcode. Eine Regel ruft sie ueber "check": {"typ": "baustein", "name": "<ID>"} auf;
// Regeln ohne "check" mit gleichnamigem Baustein nutzen diesen ebenfalls.
function runCheck(rule, cfg) {
  var spec = rule.check;
  if (!spec && !CHECKS[rule.id]) return {status:"MANUAL", findings:[], note:"Keine automatische Pruefung implementiert."};
  try {
    if (!spec) return CHECKS[rule.id](cfg);
    var typ = spec.typ || "abfrage";
    if (typ === "baustein") { if (!CHECKS[spec.name]) throw new Error("Unbekannter Baustein '" + spec.name + "'."); return CHECKS[spec.name](cfg); }
    if (typ === "reihenfolge") return _pruefeReihenfolge(spec, cfg, rule);
    if (typ === "abfrage") return _pruefeAbfrage(spec, cfg, rule);
    throw new Error("Unbekannter Pruefungstyp '" + typ + "'.");
  } catch (e) {
    return {status:"ERROR", findings:["Pruefung fehlgeschlagen: " + e], note:""};
  }
}

check("MGMT-WEBGUI-WAN",function(cfg){var gp=cfg.webguiPort();var f=[];if(!cfg.isPfsense){var b=cfg.text("system/webgui/interfaces","");if(b==="")f.push("WebGUI an KEIN Interface gebunden -> lauscht auf allen inkl. WAN.");else if(b.split(",").some(function(x){return WAN_ZONE.has(x.trim());}))f.push("WebGUI an WAN-Interface gebunden (interfaces="+b+").");}cfg.filterRules().forEach(function(r){if(r.disabled||r.type!=="pass"||!cfg.isWanZone(r.interface))return;if(r.destination.port&&cfg.resolvePorts(r.destination.port).has(gp)){if(cfg.isSelfDestination(r.destination)||r.destination.any){var s=r.source.any?"ANY":epStr(r.source);f.push("WAN-Regel #"+r.idx+" erlaubt GUI-Port "+gp+" (Quelle: "+s+") - '"+r.descr+"'.");}}});if(f.length)return{status:"FAIL",findings:f,note:cfg.isPfsense?"pfSense: GUI lauscht auf allen Interfaces.":""};return{status:"PASS",note:"GUI-Port "+gp+" nicht vom WAN freigegeben."};});
check("MGMT-SSH-WAN",function(cfg){if(!cfg.sshEnabled())return{status:"NA",note:"SSH nicht aktiviert."};var f=[];if(!cfg.isPfsense){var s=cfg.sshElement();var ifc=s?findText(s,"interfaces",""):"";if(ifc==="")f.push("SSH an KEIN Interface gebunden -> alle inkl. WAN.");else if(ifc.split(",").some(function(x){return WAN_ZONE.has(x.trim());}))f.push("SSH an WAN-Interface gebunden.");}var s=cfg.sshElement();var sp=(s?findText(s,"port",""):"")||"22";cfg.filterRules().forEach(function(r){if(r.disabled||r.type!=="pass"||!cfg.isWanZone(r.interface))return;var pts=r.destination.port?cfg.resolvePorts(r.destination.port):new Set();if(pts.has("22")||(sp!=="22"&&pts.has(sp))){var sr=r.source.any?"ANY":epStr(r.source);f.push("WAN-Regel #"+r.idx+" erlaubt SSH Port "+sp+" (Quelle: "+sr+") - '"+r.descr+"'.");}});if(f.length)return{status:"FAIL",findings:f,note:cfg.isPfsense?"pfSense: SSH auf allen Interfaces.":""};return{status:"PASS",note:"SSH nicht vom WAN erreichbar."};});
check("MGMT-ROOT-ACCOUNT",function(cfg){var named=[];var re=false;var admins=cfg.adminGroupMembers();cfg.users().forEach(function(u){var uid=findText(u,"uid",""),nm=findText(u,"name",""),dis=findText(u,"disabled","0")==="1";if(uid==="0"&&!dis)re=true;else if(admins.has(uid)&&!dis)named.push(nm);});if(re&&!named.length)return{status:"WARN",findings:["root aktiv, kein benanntes Admin-Konto."]};if(re)return{status:"WARN",findings:["root aktiv. Admins: "+named.join(", ")+". Standardpasswort pruefen."]};return{status:"PASS"};});

check("FW-HOST-CIDR",function(cfg){var f=[];function scan(ep,role,where){var toks=ep.addresses.slice();if(ep.network_kw)toks.push(ep.network_kw);toks.forEach(function(a){cfg.resolveAlias(a).forEach(function(tok){if(_hostWithSubnetMask(tok))f.push(where+" "+role+": '"+tok+"'");});});}cfg.filterRules().forEach(function(r){scan(r.source,"Quelle","Regel #"+r.idx+" '"+r.descr+"'");scan(r.destination,"Ziel","Regel #"+r.idx+" '"+r.descr+"'");});cfg.natPortForwards().forEach(function(pf){scan(pf.source,"Quelle","NAT '"+pf.descr+"'");});Object.keys(cfg.aliases).forEach(function(nm){cfg.aliases[nm].content.forEach(function(tok){if(_hostWithSubnetMask(tok))f.push("Alias '"+nm+"': '"+tok+"'");});});if(f.length)return{status:"FAIL",findings:Array.from(new Set(f)).sort()};return{status:"PASS"};});






// =====================================================================================
// === REGELSPRACHE: Pruefungen als Daten (Feld "check" einer Regel in rules.js)     ===
// =====================================================================================
// Drei Pruefungstypen:
//   "abfrage"      Werte aus der Config lesen, Eintraege (Fakten oder XML) filtern,
//                  Faelle der Reihe nach auswerten (Standardtyp)
//   "reihenfolge"  Paare "Regel A steht vor Regel B" in derselben Gruppe finden
//   "baustein"     Pruefung in Programmcode (siehe check(...) oben), Aufruf per Name
// Vollstaendige Beschreibung: SPRACHE (unten) und README.md, Abschnitt "Eigene Pruefungen".

var VPN_SCHLUESSELWOERTER = ["wireguard","openvpn","ovpn","ipsec","wg","tun","tap","vpn"];

// --- Fakten: einheitliche Sicht auf die config.xml, je Plattform normalisiert ---
Config.prototype.fakten = function() {
  var key = Array.from(WAN_ZONE).join(",");
  if (this._fakten && this._faktenKey === key) return this._fakten;
  var cfg = this, ifs = cfg.interfaces(), vpn = new Set();
  Object.keys(ifs).forEach(function(nm) {
    var el = ifs[nm], d = (findText(el,"descr","")||"").toLowerCase(), f = (findText(el,"if","")||"").toLowerCase();
    if (VPN_SCHLUESSELWOERTER.some(function(k){ return d.indexOf(k)>=0 || f.indexOf(k)>=0 || nm.indexOf(k)>=0; })) vpn.add(nm);
  });
  function ifFakt(nm) {
    var el = ifs[nm];
    return {name:nm, descr:findText(el,"descr",""), geraet:findText(el,"if",""), ist_wan:cfg.isWanZone(nm), ist_vpn:vpn.has(nm),
            block_private:isEnabled(el,"blockpriv"), block_bogons:isEnabled(el,"blockbogons")};
  }
  var posIf = {};
  var regeln = cfg.filterRules().map(function(r) {
    var el = r._el, fl = findText(el,"floating","").toLowerCase();
    posIf[r.interface] = (posIf[r.interface]||0) + 1;
    return {nr:r.idx, pos:posIf[r.interface], interface:r.interface, aktion:r.type, richtung:r.direction||"in",
      protokoll:r.protocol, ip_version:findText(el,"ipprotocol","")||"inet", aktiv:!r.disabled, log:r.log, quick:r.quick,
      floating:(fl==="yes"||fl==="1"||fl==="true"),
      zusatzbedingung:["sched","tagged","os"].some(function(t){ return findText(el,t,"")!==""; }),
      descr:r.descr, quelle_any:r.source.any, quelle_negiert:!!r.source.invert, ziel_any:r.destination.any, ziel_negiert:!!r.destination.invert,
      quelle_anzeige:r.source.any?"ANY":epStr(r.source), quelle_text:epStr(r.source), ziel_text:epStr(r.destination),
      ziel_port:r.destination.port||"", ist_wan:cfg.isWanZone(r.interface), ist_vpn:vpn.has(r.interface)};
  });
  var nat = cfg.natPortForwards().map(function(pf, i) {
    return {nr:i, interface:pf.interface, quelle_any:pf.source.any, quelle_anzeige:pf.source.any?"ANY":epStr(pf.source),
            quelle_text:epStr(pf.source), ports:pf.destPort||pf.localPort||"", ziel:pf.target, ziel_port_intern:pf.localPort,
            descr:pf.descr, ist_wan:cfg.isWanZone(pf.interface)};
  });
  var admins = cfg.adminGroupMembers();
  var benutzer = cfg.users().map(function(u) {
    var uid = findText(u,"uid",""), ak = findEl(u,"apikeys");
    return {name:findText(u,"name",""), uid:uid, aktiv:findText(u,"disabled","0")!=="1", otp:findText(u,"otp_seed","").trim()!=="",
            admin:admins.has(uid)||uid==="0", gruppen_admin:admins.has(uid), api_schluessel:ak?ak.children.length:0};
  });
  var ids = cfg.isPfsense ? _pfsenseIds(cfg) : {pkgname:null, items:[]};
  var idsInst = ids.items.map(function(it) {
    return {interface:findText(it,"interface",""), aktiv:isEnabled(it,"enable"),
            blockiert:isEnabled(it,"blockoffenders")||isEnabled(it,"blockoffenders7")||(findText(it,"ips_mode","")||"").toLowerCase().indexOf("inline")>=0};
  });
  var wg = cfg.nestedFind("wireguard")||findEl(cfg.root,"installedpackages/wireguard")||findEl(cfg.root,"wireguard"), nS=0, nC=0, nT=0, nP=0;
  if (wg) {
    var srv = findEl(wg,"server"), cli = findEl(wg,"client");
    nS = (srv?findAll(srv,"server").length:0) + iterAll(wg,"server > servers > server").length;
    nC = (cli?findAll(cli,"client").length:0) + iterAll(wg,"client > clients > client").length;
    nT = iterAll(wg,"tunnels > item").length + iterAll(wg,"tunnel").length;
    nP = iterAll(wg,"peers > item").length + iterAll(wg,"peer").length;
  }
  this._faktenKey = key;
  this._fakten = {
    quellen: {filterregeln:regeln, nat:nat, benutzer:benutzer, interfaces:Object.keys(ifs).map(ifFakt),
              wan_interfaces:Array.from(WAN_ZONE).filter(function(nm){ return !!ifs[nm]; }).map(ifFakt), ids_instanzen:idsInst},
    allgemein: {plattform:cfg.platform, ssh_aktiv:cfg.sshEnabled(), ids_paket:ids.pkgname?ids.pkgname.charAt(0).toUpperCase()+ids.pkgname.slice(1):"",
                wg_vorhanden:!!wg, wg_tunnel:nS+nT, wg_peers:nC+nP, wg_gesamt:nS+nC+nT+nP}
  };
  return this._fakten;
};

// --- XML-Pfade: "a/b/c" (Kinder-Kette), "a/*" (alle Kinder), "//name" (erstes Vorkommen irgendwo) ---
function _pfadFuer(spec, cfg) {
  if (spec && typeof spec === "object" && !Array.isArray(spec)) return spec.hasOwnProperty(cfg.platform) ? spec[cfg.platform] : null;
  return spec;
}
function waehleAlle(basis, pfad) {
  if (!basis || !pfad) return [];
  if (pfad.indexOf("//") === 0) {
    var rest = pfad.slice(2), i = rest.indexOf("/"), erst = iterAll(basis, i<0 ? rest : rest.slice(0,i))[0];
    if (!erst) return [];
    return i < 0 ? [erst] : waehleAlle(erst, rest.slice(i+1));
  }
  var ps = pfad.split("/"), letzt = ps.pop(), el = ps.length ? findEl(basis, ps.join("/")) : basis;
  if (!el) return [];
  return letzt === "*" ? Array.from(el.children) : findAll(el, letzt);
}
function waehleEins(basis, pfad) { return waehleAlle(basis, pfad)[0] || null; }
function _text(basis, pfad) { var el = waehleEins(basis, pfad); return el ? elText(el) : null; }
function _eingeschaltet(basis, pfad) {
  var i = pfad.lastIndexOf("/");
  if (i < 0) return isEnabled(basis, pfad);
  return isEnabled(waehleEins(basis, pfad.slice(0,i)), pfad.slice(i+1));
}

// --- Werte: benannte Angaben aus der Config, einmal je Pruefung gelesen ---
function _werte(def, cfg) {
  var out = {};
  Object.keys(def || {}).forEach(function(n) {
    var d = def[n], v;
    if (d.anzahl !== undefined) {
      v = 0; [].concat(d.anzahl).forEach(function(p){ p = _pfadFuer(p, cfg); if (p) v += waehleAlle(cfg.root, p).length; });
    } else if (d.verbinde !== undefined) {
      v = [].concat(d.verbinde).map(function(p){ p = _pfadFuer(p, cfg); return (p && _text(cfg.root, p)) || ""; })
            .filter(Boolean).join(d.trenner !== undefined ? d.trenner : ", ");
    } else {
      var ps = [].concat(_pfadFuer(d.pfad, cfg) || []), gef = false; v = null;
      for (var i = 0; i < ps.length; i++) { var t = _text(cfg.root, ps[i]); if (t !== null) { gef = true; if (t !== "") { v = t; break; } } }
      if (v === null) v = gef ? "" : (d.standard !== undefined ? String(d.standard) : "");
      if (d.klein) v = v.toLowerCase();
    }
    out[n] = v;
  });
  return out;
}

// --- Parameter (@param:name) und Kontext ---
var PARAM_WERTE = {};   // von applyCatalog befuellt: gepruefte Werte der fest verdrahteten Parameter
function _wert(v, ktx) {
  if (Array.isArray(v)) {   // Listen duerfen Parameter enthalten: ["@param:ports", 8443] -> Werte werden eingefuegt
    var out = [];
    v.forEach(function(x){ var r = _wert(x, ktx); if (Array.isArray(r) || r instanceof Set) out = out.concat(_liste(r)); else out.push(r); });
    return out;
  }
  if (typeof v === "string" && v.indexOf("@param:") === 0) {
    var n = v.slice(7), id = ktx.rule && ktx.rule.id;
    if (PARAM_WERTE[id] && PARAM_WERTE[id][n] !== undefined) return PARAM_WERTE[id][n];
    if (ktx.rule && ktx.rule.params && ktx.rule.params[n] !== undefined) return ktx.rule.params[n];
    throw new Error("Parameter '" + n + "' ist in der Regel nicht definiert.");
  }
  return v;
}
function _ktx(cfg, fakten, rule, item, extra) {
  var k = {cfg:cfg, fakten:fakten, rule:rule, item:item, extra:extra||{}, werte:{}, treffer:[], quellenLeer:false, liste:""};
  k.basis = function(){ return (k.item && typeof k.item.nodeType === "number") ? k.item : cfg.root; };
  k.fuer = function(it, ex){ var c = _ktx(cfg, fakten, rule, it, ex); c.werte = k.werte; return c; };
  return k;
}
function _pfadWert(o, name) {
  var ps = name.split("."), v = o;
  for (var i = 0; i < ps.length; i++) { if (v == null || typeof v !== "object" || !(ps[i] in v)) return undefined; v = v[ps[i]]; }
  return v;
}
function _feld(name, ktx) {
  var it = ktx.item;
  if (it != null) {
    if (typeof it.nodeType === "number") { var el = findEl(it, name); if (el) return elText(el); }
    else { var v = _pfadWert(it, name); if (v !== undefined) return v; }
  }
  if (ktx.extra.hasOwnProperty(name)) return ktx.extra[name];
  if (ktx.werte.hasOwnProperty(name)) return ktx.werte[name];
  if (ktx.fakten.allgemein.hasOwnProperty(name)) return ktx.fakten.allgemein[name];
  return undefined;
}

// --- Vergleiche und Operatoren (Texte: ohne Gross-/Kleinschreibung, ohne Leerzeichen am Rand) ---
function _norm(v) { return v == null ? "" : String(v).trim().toLowerCase(); }
function _liste(v) { return v instanceof Set ? Array.from(v) : [].concat(v); }
function _gleich(ist, soll) {
  if (typeof soll === "boolean") return !!ist === soll;
  if (typeof soll === "number") return Number(ist) === soll;
  return _norm(ist) === _norm(soll);
}
var OPERATOREN = {
  ist:              function(v,w){ return _gleich(v,w); },
  ist_eine_von:     function(v,w){ return _liste(w).some(function(x){ return _gleich(v,x); }); },
  leer:             function(v,w){ return (_norm(v) === "") === !!w; },
  enthaelt_eins_von:function(v,w){ var s = _norm(v); return _liste(w).some(function(x){ return s.indexOf(_norm(x)) >= 0; }); },
  liste_enthaelt:   function(v,w){ var t = _norm(v).split(/[\s,]+/).filter(Boolean); return _liste(w).some(function(x){ return t.indexOf(_norm(x)) >= 0; }); },
  groesser:         function(v,w){ return Number(v) > Number(w); },
  kleiner:          function(v,w){ return Number(v) < Number(w); },
  port_ist:         function(v,w,k){ if (!v) return false; var p = k.cfg.resolvePorts(String(v)); return _liste(w).some(function(x){ return p.has(String(x)); }); },
  ports_schneiden:  function(v,w,k){
    var hit = _portsInSet(v||"", k.cfg, new Set(_liste(w).map(Number)));
    if (!hit.size) return false;
    k.extra.treffer_ports = Array.from(hit).sort(function(a,b){ return a-b; }).join(",");
    return true;
  }
};
var BEDINGUNG_WOERTER = ["treffer","keine_treffer","quellen_leer"];
function _bed(c, ktx) {
  if (c === undefined || c === null) return true;
  if (typeof c === "string") {
    if (c === "treffer") return ktx.treffer.length > 0;
    if (c === "keine_treffer") return ktx.treffer.length === 0;
    if (c === "quellen_leer") return ktx.quellenLeer;
    throw new Error("Unbekannte Bedingung '" + c + "'.");
  }
  if (Array.isArray(c)) return c.every(function(x){ return _bed(x, ktx); });
  var keys = Object.keys(c);
  for (var i = 0; i < keys.length; i++) {
    var k = keys[i], w = c[k], ok;
    if (k === "und") ok = _liste(w).every(function(x){ return _bed(x, ktx); });
    else if (k === "oder") ok = _liste(w).some(function(x){ return _bed(x, ktx); });
    else if (k === "nicht") ok = !_bed(w, ktx);
    else if (k === "feld") {
      var ops = keys.filter(function(x){ return OPERATOREN.hasOwnProperty(x); });
      if (ops.length !== 1) throw new Error("Bedingung mit 'feld' braucht genau einen Operator.");
      ok = OPERATOREN[ops[0]](_feld(w, ktx), _wert(c[ops[0]], ktx), ktx);
    }
    else if (OPERATOREN.hasOwnProperty(k) && c.feld !== undefined) continue;
    else if (k === "eingeschaltet") { var p1 = _pfadFuer(w, ktx.cfg); ok = !!p1 && _eingeschaltet(ktx.basis(), p1); }
    else if (k === "existiert") { var p2 = _pfadFuer(w, ktx.cfg); ok = !!p2 && !!waehleEins(ktx.basis(), p2); }
    else if (k === "eine" || k === "keine") { var n = _abfrage(w, ktx).treffer.length; ok = (k === "eine") ? n > 0 : n === 0; }
    else if (k === "treffer_mit") ok = ktx.treffer.some(function(t){ return _bed(w, ktx.fuer(t.item, t.extra)); });
    else { var soll = _wert(w, ktx), ist = _feld(k, ktx);
           ok = (Array.isArray(soll) || soll instanceof Set) ? OPERATOREN.ist_eine_von(ist, soll) : _gleich(ist, soll); }
    if (!ok) return false;
  }
  return true;
}

// --- Textvorlagen: {feld}, {feld|Ersatz}, {feld:klein}, {?feld=Text}, {liste}; Punkt fuer Unterfelder: {vorher.nr} ---
function _vorlage(t, ktx) {
  return String(t)
    .replace(/\{\?([^{}=]+)=([^{}]*)\}/g, function(_, f, txt) {
      var v = _feld(f.trim(), ktx);
      return (v === true || (typeof v === "number" && v !== 0) || (typeof v === "string" && v !== "" && v !== "0")) ? txt : "";
    })
    .replace(/\{([^{}:|?]+)(?::(klein|gross))?(?:\|([^{}]*))?\}/g, function(_, f, fil, std) {
      f = f.trim();
      var v = (f === "liste") ? ktx.liste : _feld(f, ktx);
      if (v === undefined || v === null || v === "") v = (std !== undefined) ? std : "";
      v = String(v);
      if (fil === "klein") v = v.toLowerCase();
      if (fil === "gross") v = v.toUpperCase();
      return v;
    });
}

// --- Abfragen und Ergebnis-Faelle ---
function _quelleItems(q, ktx) {
  if (q.quelle !== undefined) {
    if (!ktx.fakten.quellen.hasOwnProperty(q.quelle)) throw new Error("Unbekannte Quelle '" + q.quelle + "'.");
    return ktx.fakten.quellen[q.quelle];
  }
  if (q.xml !== undefined) { var p = _pfadFuer(q.xml, ktx.cfg); return p ? waehleAlle(ktx.cfg.root, p) : []; }
  throw new Error("Abfrage braucht 'quelle' oder 'xml'.");
}
function _abfrage(q, ktx) {
  if (q.plattform && !_gleich(ktx.cfg.platform, q.plattform)) return {items:[], treffer:[]};
  var items = _quelleItems(q, ktx), tr = [];
  items.forEach(function(it) {
    var k = ktx.fuer(it);
    if (_bed(q.wo, k)) tr.push({item:it, extra:k.extra, text:(q.vorlage !== undefined) ? _vorlage(q.vorlage, k) : ""});
  });
  return {items:items, treffer:tr};
}
function _ergebnis(spec, ktx, treffer, leer) {
  ktx.treffer = treffer; ktx.quellenLeer = leer;
  var texte = treffer.map(function(t){ return t.text; });
  ktx.liste = texte.join(spec.trenner !== undefined ? spec.trenner : ", ");
  var faelle = spec.ergebnis || [];
  for (var i = 0; i < faelle.length; i++) {
    var fa = faelle[i];
    if (!_bed(fa.wenn, ktx)) continue;
    var out = {status:fa.status, findings:[], note:(fa.notiz !== undefined) ? _vorlage(fa.notiz, ktx) : ""};
    if (fa.befunde === "je_treffer") out.findings = texte.slice();
    else if (fa.befund !== undefined) out.findings = [_vorlage(fa.befund, ktx)];
    if (fa.schweregrad !== undefined) out.severity_override = _wert(fa.schweregrad, ktx);
    out.treffer = treffer.length;
    return out;
  }
  throw new Error("Kein Fall in 'ergebnis' trifft zu. Als letzten Fall einen Standardfall ohne 'wenn' anlegen.");
}
function _pruefeAbfrage(spec, cfg, rule) {
  var ktx = _ktx(cfg, cfg.fakten(), rule, null);
  ktx.werte = _werte(spec.werte, cfg);
  var abf = spec.abfragen || ((spec.quelle !== undefined || spec.xml !== undefined)
            ? [{quelle:spec.quelle, xml:spec.xml, wo:spec.wo, vorlage:spec.vorlage}] : []);
  var treffer = [], anzahl = 0;
  abf.forEach(function(q){ var r = _abfrage(q, ktx); anzahl += r.items.length; treffer = treffer.concat(r.treffer); });
  if (spec.sortierung && spec.sortierung.zuerst !== undefined) {
    var a = [], b = [];
    treffer.forEach(function(t){ (_bed(spec.sortierung.zuerst, ktx.fuer(t.item, t.extra)) ? a : b).push(t); });
    treffer = a.concat(b);
  }
  return _ergebnis(spec, ktx, treffer, anzahl === 0);
}
var UMFASST = {
  ip_version: function(a, b){ a = _norm(a); b = _norm(b); return a === b || a === "inet46"; }
};
function _pruefeReihenfolge(spec, cfg, rule) {
  var ktx = _ktx(cfg, cfg.fakten(), rule, null);
  ktx.werte = _werte(spec.werte, cfg);
  var items = _quelleItems({quelle:spec.quelle}, ktx), treffer = [];
  items.forEach(function(b, j) {
    if (!_bed(spec.nachher, ktx.fuer(b))) return;
    for (var i = 0; i < j; i++) {
      var a = items[i];
      if (!(spec.gleich||[]).every(function(g){ return _norm(_pfadWert(a,g)) === _norm(_pfadWert(b,g)); })) continue;
      if (!(spec.umfasst||[]).every(function(g){ return UMFASST[g](_pfadWert(a,g), _pfadWert(b,g)); })) continue;
      if (!_bed(spec.vorher, ktx.fuer(a))) continue;
      var paar = {vorher:a, nachher:b};
      (spec.gleich||[]).forEach(function(g){ paar[g] = _pfadWert(b, g); });
      var k = ktx.fuer(paar);
      treffer.push({item:paar, extra:k.extra, text:(spec.vorlage !== undefined) ? _vorlage(spec.vorlage, k) : ""});
      break;
    }
  });
  return _ergebnis(spec, ktx, treffer, items.length === 0);
}

// --- Beschreibung der Sprache (fuer Editor und Pruefung der Definition) ---
var SPRACHE = {
  quellen: {
    filterregeln: {text:"Firewall-Regeln unter Firewall → Rules, in der Reihenfolge der config.xml (Floating-Regeln eingeschlossen).",
      felder:{nr:"laufende Nummer ueber alle Regeln (wie im Bericht #n)", pos:"Position innerhalb des Interfaces (1, 2, …)", interface:"Interface-Name (wan, lan, opt1 …)",
        aktion:"pass, block oder reject", richtung:"in oder out (leer = in)", protokoll:"tcp, udp, any …", ip_version:"inet, inet6 oder inet46",
        aktiv:"true, wenn nicht deaktiviert", log:"Logging an", quick:"quick gesetzt", floating:"Floating-Regel", zusatzbedingung:"Zeitplan, tagged oder OS-Filter gesetzt",
        descr:"Beschreibung", quelle_any:"Quelle any", quelle_negiert:"Quelle mit 'not'", ziel_any:"Ziel any", ziel_negiert:"Ziel mit 'not'",
        quelle_anzeige:"Quelle als Text, any als ANY", quelle_text:"Quelle als Text", ziel_text:"Ziel als Text", ziel_port:"Zielport bzw. Port-Alias (leer = alle)",
        ist_wan:"Interface zaehlt als WAN (Katalog-Einstellung)", ist_vpn:"Interface ist ein VPN-Interface"}},
    nat: {text:"Port-Weiterleitungen unter Firewall → NAT → Port Forward.",
      felder:{nr:"laufende Nummer", interface:"Interface", quelle_any:"Quelle any", quelle_anzeige:"Quelle als Text, any als ANY", quelle_text:"Quelle als Text",
        ports:"Zielport(s) bzw. Port-Alias", ziel:"interne Ziel-IP", ziel_port_intern:"interner Port", descr:"Beschreibung", ist_wan:"auf WAN"}},
    benutzer: {text:"Lokale Benutzerkonten.",
      felder:{name:"Anmeldename", uid:"Benutzer-ID", aktiv:"nicht deaktiviert", otp:"OTP-Seed hinterlegt", admin:"Mitglied einer Gruppe mit page-all oder uid 0",
        gruppen_admin:"Mitglied einer Gruppe mit page-all", api_schluessel:"Anzahl API-Schluessel"}},
    interfaces: {text:"Alle Interfaces aus <interfaces>.",
      felder:{name:"interner Name (wan, lan, opt1 …)", descr:"Beschreibung", geraet:"Geraetename (igb0 …)", ist_wan:"zaehlt als WAN", ist_vpn:"VPN-Interface",
        block_private:"'Block private networks' an", block_bogons:"'Block bogon networks' an"}},
    wan_interfaces: {text:"Die WAN-Interfaces in der Reihenfolge der Katalog-Einstellung (nur vorhandene). Felder wie 'interfaces'.", felder:{}},
    ids_instanzen: {text:"pfSense: Interface-Instanzen des IDS-Pakets (Suricata/Snort).",
      felder:{interface:"Interface", aktiv:"Instanz aktiviert", blockiert:"Block Offenders bzw. Inline-Modus"}}
  },
  allgemein: {plattform:"opnsense oder pfsense", ssh_aktiv:"SSH-Dienst aktiviert", ids_paket:"pfSense: 'Suricata' oder 'Snort', sonst leer",
    wg_vorhanden:"WireGuard-Konfiguration vorhanden", wg_tunnel:"Anzahl WireGuard-Tunnel/Instanzen", wg_peers:"Anzahl WireGuard-Peers", wg_gesamt:"Tunnel + Peers"},
  operatoren: {ist:"gleich (Text ohne Gross/klein, true/false, Zahl)", ist_eine_von:"gleich einem Wert der Liste", leer:"true: Feld ist leer; false: Feld hat Inhalt",
    enthaelt_eins_von:"Text enthaelt einen der Teiltexte", liste_enthaelt:"durch Komma/Leerzeichen getrennte Liste enthaelt einen der Werte",
    groesser:"Zahl groesser", kleiner:"Zahl kleiner", port_ist:"Port bzw. aufgeloester Port-Alias enthaelt einen der Ports",
    ports_schneiden:"Ports (mit Bereichen und Aliassen) ueberschneiden sich mit der Liste; Treffer als {treffer_ports}"},
  sonder: {und:"alle Bedingungen der Liste", oder:"mindestens eine Bedingung der Liste", nicht:"Bedingung trifft nicht zu",
    "feld + Operator":"{\"feld\":\"ports\",\"ports_schneiden\":[22,3389]}", eingeschaltet:"Schalter unter dem XML-Pfad ist an (1, yes, on, enabled oder leeres Element)",
    existiert:"XML-Pfad ist vorhanden", eine:"mindestens ein Eintrag der Abfrage {quelle|xml, wo}", keine:"kein Eintrag der Abfrage {quelle|xml, wo}",
    treffer_mit:"mindestens ein Treffer erfuellt die Bedingung", "\"treffer\" / \"keine_treffer\" / \"quellen_leer\"":"als Wert von 'wenn'"}
};
var PRUEF_TYPEN = {
  abfrage:     ["typ","werte","quelle","xml","wo","vorlage","abfragen","sortierung","trenner","ergebnis"],
  reihenfolge: ["typ","werte","quelle","gleich","umfasst","vorher","nachher","vorlage","trenner","ergebnis"],
  baustein:    ["typ","name"]
};
var STATUS_WERTE = ["FAIL","WARN","PASS","NA","MANUAL"];

// Prueft eine check-Definition auf Aufbaufehler. Rueckgabe: Liste von Fehlertexten (leer = in Ordnung).
function pruefeDefinition(spec, rule) {
  var e = [];
  if (!spec || typeof spec !== "object" || Array.isArray(spec)) return ["Die Pruefung muss ein JSON-Objekt sein."];
  var typ = spec.typ || "abfrage";
  if (!PRUEF_TYPEN[typ]) return ["Unbekannter Typ '" + typ + "' (erlaubt: " + Object.keys(PRUEF_TYPEN).join(", ") + ")."];
  Object.keys(spec).forEach(function(k){ if (PRUEF_TYPEN[typ].indexOf(k) < 0) e.push("Unbekannter Schluessel '" + k + "' fuer Typ " + typ + "."); });
  if (typ === "baustein") {
    if (!CHECKS[spec.name]) e.push("Unbekannter Baustein '" + spec.name + "' (vorhanden: " + Object.keys(CHECKS).join(", ") + ").");
    return e;
  }
  Object.keys(spec.werte || {}).forEach(function(n) {
    var d = spec.werte[n], arten = ["pfad","anzahl","verbinde"].filter(function(a){ return d && d[a] !== undefined; });
    if (arten.length !== 1) e.push("Wert '" + n + "': genau eine Art angeben (pfad, anzahl oder verbinde).");
  });
  function bed(c, wo) {
    if (c === undefined || c === null) return;
    if (typeof c === "string") { if (BEDINGUNG_WOERTER.indexOf(c) < 0) e.push(wo + ": unbekannte Bedingung '" + c + "'."); return; }
    if (Array.isArray(c)) { c.forEach(function(x){ bed(x, wo); }); return; }
    if (typeof c !== "object") { e.push(wo + ": Bedingung muss ein Objekt sein."); return; }
    if (c.feld !== undefined) {
      var ops = Object.keys(c).filter(function(x){ return OPERATOREN.hasOwnProperty(x); });
      if (ops.length !== 1) e.push(wo + ": 'feld' braucht genau einen Operator (" + Object.keys(OPERATOREN).join(", ") + ").");
    } else {
      Object.keys(c).forEach(function(k){ if (OPERATOREN.hasOwnProperty(k)) e.push(wo + ": Operator '" + k + "' ohne 'feld'."); });
    }
    Object.keys(c).forEach(function(k) {
      if (k === "und" || k === "oder") _liste(c[k]).forEach(function(x){ bed(x, wo); });
      else if (k === "nicht" || k === "treffer_mit") bed(c[k], wo);
      else if (k === "eine" || k === "keine") abf(c[k], wo + " → " + k);
    });
  }
  function abf(q, wo) {
    if (!q || typeof q !== "object") { e.push(wo + ": Abfrage muss ein Objekt sein."); return; }
    Object.keys(q).forEach(function(k){ if (["plattform","quelle","xml","wo","vorlage"].indexOf(k) < 0) e.push(wo + ": unbekannter Schluessel '" + k + "'."); });
    if (q.quelle === undefined && q.xml === undefined) e.push(wo + ": 'quelle' oder 'xml' fehlt.");
    if (q.quelle !== undefined && !SPRACHE.quellen[q.quelle]) e.push(wo + ": unbekannte Quelle '" + q.quelle + "' (vorhanden: " + Object.keys(SPRACHE.quellen).join(", ") + ").");
    bed(q.wo, wo + " → wo");
  }
  if (typ === "abfrage") {
    if (spec.abfragen !== undefined) {
      if (!Array.isArray(spec.abfragen)) e.push("'abfragen' muss eine Liste sein.");
      else spec.abfragen.forEach(function(q, i){ abf(q, "abfragen[" + (i+1) + "]"); });
      if (spec.quelle !== undefined || spec.xml !== undefined) e.push("Entweder 'abfragen' oder 'quelle'/'xml' verwenden, nicht beides.");
    } else if (spec.quelle !== undefined || spec.xml !== undefined) {
      abf({quelle:spec.quelle, xml:spec.xml, wo:spec.wo, vorlage:spec.vorlage}, "Abfrage");
    }
    if (spec.sortierung !== undefined) bed(spec.sortierung.zuerst, "sortierung");
  }
  if (typ === "reihenfolge") {
    if (!SPRACHE.quellen[spec.quelle]) e.push("'reihenfolge' braucht eine Faktenquelle in 'quelle' (z. B. filterregeln).");
    (spec.umfasst || []).forEach(function(g){ if (!UMFASST[g]) e.push("'umfasst' kennt nur: " + Object.keys(UMFASST).join(", ") + "."); });
    bed(spec.vorher, "vorher"); bed(spec.nachher, "nachher");
  }
  if (!Array.isArray(spec.ergebnis) || !spec.ergebnis.length) e.push("'ergebnis' fehlt (Liste von Faellen).");
  else {
    spec.ergebnis.forEach(function(f, i) {
      var wo = "ergebnis[" + (i+1) + "]";
      Object.keys(f).forEach(function(k){ if (["wenn","status","schweregrad","befund","befunde","notiz"].indexOf(k) < 0) e.push(wo + ": unbekannter Schluessel '" + k + "'."); });
      if (STATUS_WERTE.indexOf(f.status) < 0) e.push(wo + ": 'status' muss einer von " + STATUS_WERTE.join(", ") + " sein.");
      if (f.befunde !== undefined && f.befunde !== "je_treffer") e.push(wo + ": 'befunde' kennt nur \"je_treffer\".");
      if (f.schweregrad !== undefined && !SEV_ORDER.hasOwnProperty(f.schweregrad) && String(f.schweregrad).indexOf("@param:") !== 0)
        e.push(wo + ": ungueltiger 'schweregrad' (critical, high, medium, low, info oder @param:name).");
      bed(f.wenn, wo + " → wenn");
    });
    if (spec.ergebnis[spec.ergebnis.length-1].wenn !== undefined) e.push("Der letzte Fall in 'ergebnis' sollte ohne 'wenn' sein (Standardfall).");
  }
  var js = JSON.stringify(spec), re = /"@param:([^"]+)"/g, m;
  while ((m = re.exec(js))) {
    var n = m[1], id = rule && rule.id;
    var ok = (PARAM_SPEC.rules[id] && PARAM_SPEC.rules[id][n] !== undefined) || (rule && rule.params && rule.params[n] !== undefined);
    if (!ok) e.push("Parameter '" + n + "' ist in dieser Regel nicht definiert (unter 'params' anlegen).");
  }
  return e;
}

// Fuehrt eine einzelne Regel gegen eine config.xml aus (fuer den Probelauf im Editor).
function probelauf(rule, xmlText, catalog) {
  var root = new DOMParser().parseFromString(xmlText, "text/xml").documentElement;
  if (!root || (root.tagName !== "opnsense" && root.tagName !== "pfsense")) throw new Error("Keine OPNsense- oder pfSense-config.xml.");
  applyCatalog(catalog);
  var cfg = new Config(root), r = runCheck(rule, cfg);
  return {platform:cfg.platform, status:r.status, severity:r.severity_override || rule.severity,
          findings:r.findings || [], note:r.note || "", treffer:r.treffer};
}

// === PARAMETER AUS DEM KATALOG (rules.js) ===
// Welche Werte aus rules.js wirken. Der Regel-Editor liest diese Beschreibung, um sie anzuzeigen.
var PARAM_SPEC = {
  meta: {
    wan_interfaces: "Interface-Namen, die als WAN (Internetseite) gelten, z. B. [\"wan\", \"opt2\"]. Standard: [\"wan\"].",
    scoring: "penalty_fail / penalty_warn / penalty_pass: Anteil des Gewichts, der bei FAIL/WARN/OK als Strafpunkte zaehlt. Standard 1.0 / 0.5 / 0.0."
  },
  rules: {
    "NAT-MGMT-EXPOSED": {sensitive_ports: "Portnummern (1-65535), deren Weiterleitung vom WAN als sensibel gilt."},
    "SVC-SNMP-PUBLIC": {default_communities: "Community-Namen, die als unsichere Standardwerte gelten (Gross-/Kleinschreibung egal)."},
    "FW-ANY-ANY": {wan_zone_severity: "Schweregrad, wenn eine any-any-Regel auf einem WAN-Interface liegt (critical, high, medium, low, info)."}
  }
};

function _ruleParams(catalog, id) {
  var r = (catalog.rules || []).find(function(x){ return x.id === id; });
  return (r && r.params && typeof r.params === "object") ? r.params : {};
}
function _num(v, d) { return (typeof v === "number" && isFinite(v) && v >= 0) ? v : d; }

function applyCatalog(catalog) {
  var m = (catalog && catalog.meta) || {};
  var wan = Array.isArray(m.wan_interfaces) ? m.wan_interfaces.filter(function(x){ return typeof x === "string" && x.trim(); }).map(function(x){ return x.trim(); }) : [];
  WAN_ZONE = new Set(wan.length ? wan : DEFAULTS.wan_interfaces);

  var sc = m.scoring || {};
  PENALTY_FACTOR = {FAIL: _num(sc.penalty_fail, DEFAULTS.penalty.FAIL),
                    WARN: _num(sc.penalty_warn, DEFAULTS.penalty.WARN),
                    PASS: _num(sc.penalty_pass, DEFAULTS.penalty.PASS)};

  var sp = _ruleParams(catalog, "NAT-MGMT-EXPOSED").sensitive_ports;
  sp = Array.isArray(sp) ? sp.filter(function(x){ return Number.isInteger(x) && x >= 1 && x <= 65535; }) : [];
  SENSITIVE_PORTS = new Set(sp.length ? sp : DEFAULTS.sensitive_ports);

  var dc = _ruleParams(catalog, "SVC-SNMP-PUBLIC").default_communities;
  dc = Array.isArray(dc) ? dc.filter(function(x){ return typeof x === "string" && x.trim(); }).map(function(x){ return x.trim().toLowerCase(); }) : [];
  SNMP_DEFAULT_COMMUNITIES = new Set(dc.length ? dc : DEFAULTS.default_communities);

  var ws = _ruleParams(catalog, "FW-ANY-ANY").wan_zone_severity;
  FW_ANY_WAN_SEVERITY = (typeof ws === "string" && SEV_ORDER.hasOwnProperty(ws)) ? ws : DEFAULTS.wan_zone_severity;

  PARAM_WERTE = {"NAT-MGMT-EXPOSED": {sensitive_ports: SENSITIVE_PORTS},
                 "SVC-SNMP-PUBLIC":  {default_communities: SNMP_DEFAULT_COMMUNITIES},
                 "FW-ANY-ANY":       {wan_zone_severity: FW_ANY_WAN_SEVERITY}};
}

// === SCORING ===
function runAudit(cfg, catalog) {
  applyCatalog(catalog);
  var results = [];
  catalog.rules.forEach(function(rule) {
    if (rule.enabled === false) return;
    var res = runCheck(rule, cfg);
    results.push({
      rule: rule,
      status: res.status,
      severity: res.severity_override || rule.severity,
      findings: res.findings || [],
      note: res.note || ""
    });
  });
  return results;
}

function scoreResults(results, catalog) {
  applyCatalog(catalog);
  var w = catalog.meta.severity_weights;
  var penalty = 0.0, maxPenalty = 0.0;
  var counts = {FAIL:0,WARN:0,PASS:0,NA:0,MANUAL:0,ERROR:0};
  var sevFail = {critical:0,high:0,medium:0,low:0,info:0};
  results.forEach(function(r) {
    counts[r.status] = (counts[r.status]||0)+1;
    if (NON_SCORED.has(r.status) || r.status === "ERROR") return;
    var weight = w[r.severity] || 0;
    maxPenalty += weight;
    penalty += weight * (PENALTY_FACTOR[r.status] || 0.0);
    if ((r.status==="FAIL"||r.status==="WARN") && sevFail[r.severity]!==undefined) sevFail[r.severity]++;
  });
  var posture = maxPenalty===0 ? 100.0 : Math.round(100*(1-penalty/maxPenalty)*10)/10;
  var grade = posture>=90?"A":posture>=80?"B":posture>=70?"C":posture>=60?"D":"F";
  return {posture:posture,grade:grade,penalty:Math.round(penalty*10)/10,maxPenalty:Math.round(maxPenalty*10)/10,counts:counts,severity_findings:sevFail};
}

function sortResults(results) {
  var rank = {FAIL:0,WARN:1,ERROR:2,MANUAL:3,PASS:4,NA:5};
  return results.slice().sort(function(a,b) {
    var ra = rank[a.status]!==undefined?rank[a.status]:9;
    var rb = rank[b.status]!==undefined?rank[b.status]:9;
    if (ra!==rb) return ra-rb;
    var sa = SEV_ORDER[a.severity]||0, sb = SEV_ORDER[b.severity]||0;
    if (sa!==sb) return sb-sa;
    return a.rule.id < b.rule.id ? -1 : a.rule.id > b.rule.id ? 1 : 0;
  });
}

// === GESAMTLAUF: XML-Text -> Bericht ===
function auditXml(xmlText, catalog) {
  var doc = new DOMParser().parseFromString(xmlText, "text/xml");
  var root = doc.documentElement;
  if (!root || (root.tagName !== "opnsense" && root.tagName !== "pfsense")) {
    throw new Error("Wurzelelement ist <"+(root?root.tagName:"?")+">, erwartet <opnsense> oder <pfsense>.");
  }
  var cfg = new Config(root);
  var results = runAudit(cfg, catalog);
  return {
    platform: cfg.platform,
    hostname: findText(root, "system/hostname", "") + "." + findText(root, "system/domain", ""),
    summary: scoreResults(results, catalog),
    results: sortResults(results)
  };
}
