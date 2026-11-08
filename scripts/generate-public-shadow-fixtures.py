"""Synthetic Gaussian shadow prototype. No application or native browser execution."""
import base64,hashlib,json,math,pathlib,struct,zlib,subprocess
FOLDER=pathlib.Path(__file__).resolve().parent
DPR=2
QUADRATURE=4
SHAPES=[
 ('brand',38,38,11,22,0,6,(126,98,250),.25),
 ('online',7,7,3.5,12,0,0,(105,217,194),.4),
 ('topbar',6,6,3,12,0,0,(105,217,194),.4),
 ('orbit',8,8,4,14,0,0,(105,217,194),.65),
 ('core',75,75,21,50,0,0,(130,114,230),.15),
 ('core-narrow',64,64,21,50,0,0,(130,114,230),.15),
]
def cdf(value):return .5*math.erfc(-value/math.sqrt(2))
def inset(y,height,radius):
 if y<radius:return radius-math.sqrt(max(0,radius*radius-(y-radius)**2))
 if y>height-radius:return radius-math.sqrt(max(0,radius*radius-(y-height+radius)**2))
 return 0.0
def inside(x,y,width,height,radius):
 if not (0<=x<=width and 0<=y<=height):return False
 edge=inset(y,height,radius);return edge<=x<=width-edge

def png_chunk(kind,body):return struct.pack('>I',len(body))+kind+body+struct.pack('>I',zlib.crc32(kind+body)&0xffffffff)
def encode_png(width,height,rgba):
 assert len(rgba)==width*height*4
 rows=b''.join(b'\0'+rgba[y*width*4:(y+1)*width*4] for y in range(height))
 return b'\x89PNG\r\n\x1a\n'+png_chunk(b'IHDR',struct.pack('>IIBBBBB',width,height,8,6,0,0,0))+png_chunk(b'IDAT',zlib.compress(rows,9))+png_chunk(b'IEND',b'')
def decode_png(raw):
 assert raw[:8]==b'\x89PNG\r\n\x1a\n';offset=8;chunks=[];width=height=None
 while offset<len(raw):
  length=struct.unpack('>I',raw[offset:offset+4])[0];kind=raw[offset+4:offset+8];body=raw[offset+8:offset+8+length];crc=struct.unpack('>I',raw[offset+8+length:offset+12+length])[0];assert zlib.crc32(kind+body)&0xffffffff==crc
  if kind==b'IHDR':width,height,depth,color,compression,filtering,interlace=struct.unpack('>IIBBBBB',body);assert (depth,color,compression,filtering,interlace)==(8,6,0,0,0)
  elif kind==b'IDAT':chunks.append(body)
  elif kind==b'IEND':assert not body and offset+12==len(raw)
  else:raise AssertionError('Unexpected synthetic PNG chunk')
  offset+=length+12
 rows=zlib.decompress(b''.join(chunks));assert len(rows)==height*(width*4+1);assert all(rows[y*(width*4+1)]==0 for y in range(height));return width,height,b''.join(rows[y*(width*4+1)+1:(y+1)*(width*4+1)] for y in range(height))
def raster(shape):
 name,width,height,radius,blur,ox,oy,color,opacity=shape;sigma=blur/2;px=math.ceil(4*sigma+abs(ox));py=math.ceil(4*sigma+abs(oy));pw=(width+2*px)*DPR;ph=(height+2*py)*DPR
 xs=[(x+.5)/DPR-px for x in range(pw)];ys=[(y+.5)/DPR-py for y in range(ph)];dy=1/QUADRATURE;source_y=[(i+.5)*dy for i in range(height*QUADRATURE)]
 horizontal=[]
 for sy in source_y:
  left=inset(sy,height,radius);right=width-left;horizontal.append([cdf((right+ox-x)/sigma)-cdf((left+ox-x)/sigma) for x in xs])
 pixels=bytearray();alpha=[];corners=[]
 for y in ys:
  row=[0.0]*pw
  for sy,values in zip(source_y,horizontal):
   weight=cdf((sy+oy+dy/2-y)/sigma)-cdf((sy+oy-dy/2-y)/sigma)
   if weight:row=[a+weight*b for a,b in zip(row,values)]
  for x,value in zip(xs,row):
   covered=0
   if -.5/DPR<x<width+.5/DPR and -.5/DPR<y<height+.5/DPR:
    covered=sum(inside(x+(i+.5-2)/(4*DPR),y+(j+.5-2)/(4*DPR),width,height,radius) for i in range(4) for j in range(4))/16
   a=round(255*opacity*max(0,min(1,value))*(1-covered));assert 0<=a<=math.ceil(255*opacity);pixels.extend((*color,a));alpha.append(a)
 raw=encode_png(pw,ph,bytes(pixels));dw,dh,decoded=decode_png(raw);assert (dw,dh,decoded)==(pw,ph,bytes(pixels));assert encode_png(pw,ph,bytes(pixels))==raw
 assert alpha[0]==alpha[pw-1]==alpha[-pw]==alpha[-1]==0
 cx=round((px+width/2)*DPR-.5);cy=round((py+height/2)*DPR-.5);assert alpha[cy*pw+cx]==0 and max(alpha)>0
 encoded=base64.b64encode(raw).decode('ascii')
 return {'pngBase64':encoded,'name':name,'cssWidth':width,'cssHeight':height,'cornerRadius':radius,'cssBlur':blur,'sigma':sigma,'offsetX':ox,'offsetY':oy,'colorRGB':color,'opacity':opacity,'paddingX':px,'paddingY':py,'dpr':DPR,'pixelWidth':pw,'pixelHeight':ph,'pngBytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'maximumAlphaByte':max(alpha),'nonzeroAlphaPixels':sum(a>0 for a in alpha),'PNGCRCAndRoundTripVerified':True,'deterministicEncodingVerified':True,'transparentCenterAndOuterCorners':True}
def main():
 repo=FOLDER.parent
 reference='235c6cfd9f2ec32cdc165bfb8fefc7ddbefeb056'
 css=subprocess.check_output(['git','show',reference+':web/app.css'],cwd=repo)
 expected='2a60b91d0c6c04b8fa3d4fc50f948e326dc1408648ac0fda41ec37ffc77de9d6'
 assert hashlib.sha256(css).hexdigest()==expected
 keys=['name','cssWidth','cssHeight','cornerRadius','cssBlur','offsetX','offsetY','colorRGB','opacity','paddingX','paddingY','dpr','pixelWidth','pixelHeight','pngBytes','sha256','pngBase64']
 rows=[]
 for shape in SHAPES:
  row=raster(shape);rows.append({k:row[k] for k in keys});print(json.dumps({'name':row['name'],'PNGBytes':row['pngBytes'],'syntheticOnly':True}),flush=True)
 report={'schemaVersion':1,'referenceSourceCommit':reference,'referenceCSSSHA256':expected,'generatorSHA256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),'rasterDPR':DPR,'quadrature':QUADRATURE,'shapes':rows}
 (FOLDER/'browser-tests/public-shadow-fixtures.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
if __name__=='__main__':main()
