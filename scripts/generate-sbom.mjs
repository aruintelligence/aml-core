import fs from 'node:fs';
import path from 'node:path';

const pkg = JSON.parse(fs.readFileSync('package.json','utf8'));
const deps = {...(pkg.dependencies||{}), ...(pkg.optionalDependencies||{})};
const peer = pkg.peerDependencies || {};
const components = [
  ...Object.entries(deps).map(([name,version])=>({type:'library',name,version,scope:'required',purl:`pkg:npm/${encodeURIComponent(name)}@${encodeURIComponent(version)}`})),
  ...Object.entries(peer).map(([name,version])=>({type:'library',name,version,scope:'optional',purl:`pkg:npm/${encodeURIComponent(name)}@${encodeURIComponent(version)}`}))
].sort((a,b)=>a.name.localeCompare(b.name));

const sbom = {
  bomFormat:'CycloneDX',
  specVersion:'1.5',
  serialNumber:`urn:uuid:00000000-0000-5000-8000-${Buffer.from(`${pkg.name}@${pkg.version}`).toString('hex').slice(0,12).padEnd(12,'0')}`,
  version:1,
  metadata:{
    component:{type:'library',name:pkg.name,version:pkg.version,purl:`pkg:npm/${pkg.name}@${pkg.version}`,licenses:[{license:{id:pkg.license||'NOASSERTION'}}]},
    properties:[
      {name:'aml:source',value:'package-manifest'},
      {name:'aml:dependency-resolution',value:components.length===0?'no-runtime-dependencies-declared':'manifest-ranges-not-lock-resolved'},
      {name:'aml:claim-boundary',value:'Project-generated manifest-level SBOM; not an external audit or vulnerability certification.'}
    ]
  },
  components
};
const output = `${JSON.stringify(sbom,null,2)}\n`;
const target = process.argv[2];
if(target){ fs.mkdirSync(path.dirname(target),{recursive:true}); fs.writeFileSync(target,output); }
else process.stdout.write(output);
