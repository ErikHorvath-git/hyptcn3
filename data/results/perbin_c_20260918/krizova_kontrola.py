# Nezavisly prepocet per-bin vektora priamo z .vmicd suboru (Python + numpy)
# a porovnanie s tym, co do sidecaru zapisal modul v C.
import json,sys,struct
import numpy as np

vmicd, sidecar = sys.argv[1], sys.argv[2]
d=json.load(open(sidecar)); ft=d["features"]
BB=ft["bin_bytes"]; PS=ft["page_size"]
bins={b["bin"]:b for b in ft["bins"]}

with open(vmicd,"rb") as f:
    hdr=f.read(64)
    assert hdr[:8]==b"VMICDLT1"
    ps=struct.unpack_from("<I",hdr,12)[0]; n=struct.unpack_from("<Q",hdr,40)[0]
    full=struct.unpack_from("<Q",hdr,48)[0]&1
    assert ps==PS
    changed={}; ent={}
    lut=np.zeros(PS+1); c=np.arange(1,PS+1); lut[1:]=c*np.log2(c)
    log2ps=np.log2(PS)
    for _ in range(n):
        idx=struct.unpack("<Q",f.read(8))[0]
        page=np.frombuffer(f.read(PS),dtype=np.uint8)
        b=(idx*PS)//BB
        changed[b]=changed.get(b,0)+1
        h=log2ps-lut[np.bincount(page,minlength=256)].sum()/PS
        ent[b]=ent.get(b,0.0)+max(h,0.0)

print("plna snimka:",bool(full),"zaznamov:",n)
bad=0
for b,cnt in sorted(changed.items()):
    c_bin=bins.get(b)
    if c_bin is None: print("ZLE: bin",b,"v sidecari nie je"); bad+=1; continue
    if c_bin["pages_changed"]!=cnt:
        print("ZLE: bin",b,"changed C=",c_bin["pages_changed"],"py=",cnt); bad+=1
    mean=ent[b]/cnt
    if abs(mean-c_bin["entropy_mean"])>5e-6:
        print("ZLE: bin",b,"entropy C=",c_bin["entropy_mean"],"py=",round(mean,6)); bad+=1
# biny, ktore su v sidecari oznacene ako nezmenene, nesmu byt v subore
for b,c_bin in bins.items():
    if c_bin["pages_changed"] and b not in changed:
        print("ZLE: bin",b,"ma v sidecari zmeny, v subore nie"); bad+=1
# nulove stranky sa z delty odvodit nedaju (o nezmenenych strankach subor mlci)
for b,c_bin in (sorted(bins.items()) if full else []):
    zero_py=(c_bin["pages_total"]-changed.get(b,0))/c_bin["pages_total"]
    if abs(zero_py-c_bin["zero_ratio"])>1e-6:
        print("ZLE: bin",b,"zero_ratio C=",c_bin["zero_ratio"],"py=",round(zero_py,6)); bad+=1
print("binov so zmenou v subore:",len(changed),"binov v sidecari:",len(bins))
print("VYSLEDOK:","NEZHODA" if bad else "ZHODA C vs Python")
sys.exit(1 if bad else 0)
