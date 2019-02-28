const fs = require('fs');
const path = require('path');

export default (policyname) => {
    if (!['enduser', 'guardian', 'maintainer'].includes(policyname)){
        throw new Error(`Requested a policy whose name does not match any of ours: ${policyname}`)
    }
    return fs.readFileSync(path.resolve(__dirname, `${policyname}.hcl`), 'utf8');
}