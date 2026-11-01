'use strict';
const test=require('node:test');const assert=require('node:assert/strict');const {parseBenchmark}=require('./check-profile-benchmark.cjs');
const sample='goos: windows\ngoarch: arm64\npkg: github.com/Yunushan/accessweaver/internal/profile\nBenchmarkList256/serial-4 10 60000000 ns/op 1300000 B/op 6400 allocs/op\nBenchmarkList256/four_readers-4 40 15000000 ns/op 4.000 readers 390000 B/op 1600 allocs/op\nPASS\nok github.com/Yunushan/accessweaver/internal/profile 4.5s\n';
const expected={goos:'windows',goarch:'arm64'};
test('native benchmark results retain units, actual iterations and reader count',()=>{
 const rows=parseBenchmark(sample,expected);assert.equal(rows.serial.nanosecondsPerOperation,60000000);assert.equal(rows.four_readers.nanosecondsPerOperation,15000000);assert.equal(rows.four_readers.iterations,40);assert.equal(rows.four_readers.readers,4);
});
test('wrong targets, partial runs, duplicate cases and invalid metrics cannot become benchmark evidence',()=>{
 for(const broken of [sample.replace('goarch: arm64','goarch: amd64'),sample.replace('goos: windows','goos: linux'),sample.replace('PASS','FAIL'),sample.replace(/^BenchmarkList256\/serial.*\n/m,''),sample.replace('4.000 readers','8.000 readers'),sample.replace('15000000 ns/op','NaN ns/op'),sample.replace('15000000 ns/op','Infinity ns/op'),sample.replace('15000000 ns/op','0 ns/op'),sample.replace('390000 B/op','-1 B/op'),sample.replace('1600 allocs/op','1600 B/op'),sample.replace('40 15000000','0 15000000'),sample.replace('PASS','BenchmarkList256/serial-4 10 60000000 ns/op 1300000 B/op 6400 allocs/op\nPASS')])assert.throws(()=>parseBenchmark(broken,expected));
});
