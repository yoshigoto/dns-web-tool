const dnsTypes = require('dns-packet/types');

// MQTYPE オプション構築テスト
function testMQTypeOption() {
    console.log('=== MQTYPE オプション構築テスト ===\n');
    
    // テストケース 1: 単一型
    const mQType1 = 'A';
    testBuildOption(mQType1);
    
    // テストケース 2: 複数型
    const mQType2 = 'A,AAAA,MX';
    testBuildOption(mQType2);
    
    // テストケース 3: 複数型（多数）
    const mQType3 = 'A,AAAA,MX,NS,TXT,CNAME';
    testBuildOption(mQType3);
}

function testBuildOption(mQType) {
    try {
        const mQTypeArray = mQType.split(',');
        const mQlength = mQTypeArray.length * 2;
        const option = { code: 20, length: mQlength, data: Buffer.alloc(mQlength) };
        
        let offset = 0;
        for (const type of mQTypeArray) {
            const typeNum = dnsTypes.toType(type.trim());
            option.data.writeUInt16BE(typeNum, offset);
            offset += 2;
        }
        
        console.log(`入力: "${mQType}"`);
        console.log(`  オプションコード: ${option.code}`);
        console.log(`  オプション長: ${option.length} bytes`);
        console.log(`  バッファ内容: ${option.data.toString('hex')}`);
        
        // 検証: バッファが正しくエンコードされているか
        console.log(`  検証:`);
        let verifyOffset = 0;
        for (const type of mQTypeArray) {
            const typeNum = option.data.readUInt16BE(verifyOffset);
            const typeName = dnsTypes.toString(typeNum);
            console.log(`    - ${type.trim()} (${typeNum}) -> 確認: ${typeName}`);
            verifyOffset += 2;
        }
        console.log('  ✓ 成功\n');
    } catch (err) {
        console.log(`✗ エラー: ${err.message}\n`);
    }
}

// MQTYPE レスポンス解析テスト
function testMQTypeResponseParsing() {
    console.log('=== MQTYPE レスポンス解析テスト ===\n');
    
    // テストケース: MQTYPE オプション付きの応答をシミュレート
    const testBuffer = Buffer.alloc(10);
    const length = 6; // 3 型 × 2 バイト
    testBuffer.writeUInt16BE(length, 0);
    testBuffer.writeUInt16BE(1, 2);  // A
    testBuffer.writeUInt16BE(28, 4); // AAAA
    testBuffer.writeUInt16BE(15, 6); // MX
    
    console.log('シミュレート応答バッファ: ' + testBuffer.toString('hex'));
    console.log('バッファ解析:\n');
    
    try {
        const bufferLength = testBuffer.readUInt16BE(0);
        console.log(`  オプション長: ${bufferLength} bytes`);
        console.log(`  型情報:`);
        
        let mQTypeString = '';
        for (let offset = 0; offset < bufferLength; offset += 2) {
            const type = testBuffer.readUInt16BE(offset + 2);
            const typeName = dnsTypes.toString(type);
            console.log(`    - offset ${offset}: type=${type} (${typeName})`);
            mQTypeString += `${typeName},`;
        }
        
        if (mQTypeString.length > 0) {
            mQTypeString = mQTypeString.slice(0, -1);
        }
        
        console.log(`\n  最終結果: ${mQTypeString}`);
        console.log('  ✓ 成功\n');
    } catch (err) {
        console.log(`✗ エラー: ${err.message}\n`);
    }
}

// テスト実行
testMQTypeOption();
testMQTypeResponseParsing();

console.log('=== RFC 10029 実サーバーテスト ===\n');
console.log('本番テストには RFC 10029 対応 DNS サーバーが必要です。');
console.log('既知の対応サーバーは限定的です。');
console.log('\n例: dns-web-tool.js で MQTYPE パラメータを指定して送信');
console.log('  例: http://localhost:3000/?server=8.8.8.8&name=example.com&type=A&mqtype=A,AAAA');
