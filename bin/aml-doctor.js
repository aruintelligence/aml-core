#!/usr/bin/env node

import { runAmlDoctor } from "../tooling/doctor.js";

const report = runAmlDoctor();
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
process.exit(report.healthy ? 0 : 1);
