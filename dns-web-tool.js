const http = require('http');
const net = require('net');
const dgram = require('dgram');
const dnsPacket = require('dns-packet');	// https://github.com/mafintosh/dns-packet
const dnsTypes = require('dns-packet/types');

// RFC 8914 に定義されている INFO-CODE のマッピング表
const EDE_ERRORS = {
    0: '<a href="https://www.rfc-editor.org/info/rfc8914/#name-extended-dns-error-code-0-o">Other Error</a>',
    1: '<a href="https://www.rfc-editor.org/info/rfc8914/#name-extended-dns-error-code-1-u">Unsupported DNSKEY Algorithm</a>',
    2: '<a href="https://www.rfc-editor.org/info/rfc8914/#name-extended-dns-error-code-2-u">Unsupported DS Digest Type</a>',
    3: '<a href="https://www.rfc-editor.org/info/rfc8914/#name-extended-dns-error-code-3-s">Stale Answer</a>',
    4: '<a href="https://www.rfc-editor.org/info/rfc8914/#name-extended-dns-error-code-4-f">Forged Answer</a>',
    5: '<a href="https://www.rfc-editor.org/info/rfc8914/#name-extended-dns-error-code-5-d">DNSSEC Indeterminate</a>',
    6: '<a href="https://www.rfc-editor.org/info/rfc8914/#name-extended-dns-error-code-6-d">DNSSEC Bogus</a>',
    7: '<a href="https://www.rfc-editor.org/info/rfc8914/#name-extended-dns-error-code-7-s">Signature Expired</a>',
    8: '<a href="https://www.rfc-editor.org/info/rfc8914/#name-extended-dns-error-code-8-s">Signature Not Yet Valid</a>',
    9: '<a href="https://www.rfc-editor.org/info/rfc8914/#name-extended-dns-error-code-9-d">DNSKEY Missing</a>',
    10: '<a href="https://www.rfc-editor.org/info/rfc8914/#name-extended-dns-error-code-10-">RRSIGs Missing</a>',
    11: '<a href="https://www.rfc-editor.org/info/rfc8914/#name-extended-dns-error-code-11-">No Zone Key Bit Set</a>',
    12: '<a href="https://www.rfc-editor.org/info/rfc8914/#name-extended-dns-error-code-12-">NSEC Missing</a>',
    13: '<a href="https://www.rfc-editor.org/info/rfc8914/#name-extended-dns-error-code-13-">Cached Error</a>',
    14: '<a href="https://www.rfc-editor.org/info/rfc8914/#name-extended-dns-error-code-14-">Not Ready</a>',
    15: '<a href="https://www.rfc-editor.org/info/rfc8914/#name-extended-dns-error-code-15-">Blocked</a>',
    16: '<a href="https://www.rfc-editor.org/info/rfc8914/#name-extended-dns-error-code-16-">Censored</a>',
    17: '<a href="https://www.rfc-editor.org/info/rfc8914/#name-extended-dns-error-code-17-">Filtered</a>',
    18: '<a href="https://www.rfc-editor.org/info/rfc8914/#name-extended-dns-error-code-18-">Prohibited</a>',
    19: '<a href="https://www.rfc-editor.org/info/rfc8914/#name-extended-dns-error-code-19-">Stale NXDOMAIN Answer</a>',
    20: '<a href="https://www.rfc-editor.org/info/rfc8914/#name-extended-dns-error-code-20-">Not Authoritative</a>',
    21: '<a href="https://www.rfc-editor.org/info/rfc8914/#name-extended-dns-error-code-21-">Not Supported</a>',
    22: '<a href="https://www.rfc-editor.org/info/rfc8914/#name-extended-dns-error-code-22-">No Reachable Authority</a>',
    23: '<a href="https://www.rfc-editor.org/info/rfc8914/#name-extended-dns-error-code-23-">Network Error</a>',
    24: '<a href="https://www.rfc-editor.org/info/rfc8914/#name-extended-dns-error-code-24-">Invalid Data</a>'
};

// HTMLエスケープ処理 (XSSインジェクション対策)
const escapeHtml = (str) => {
    if (typeof str !== 'string') return '';
    return str.replace(/[&<>"']/g, (match) => {
        const escapes = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;'
        };
        return escapes[match];
    });
};

const addLinkToDisplayData = (origin, pathname, dnsServer, domainName, queryType, recursionDesired, checkingDisabled,
    sendTcp, sendIpv6, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, qnamePosition, qnameType, displayData, button=false, extraQuery='') => {
    let html = '<a ';
    if (button) {
        html += 'class="a-button" ';
    }
    html += `href=${origin}${pathname}?server=${escapeHtml(dnsServer)}&name=${escapeHtml(domainName)}&type=${queryType}&rd=${recursionDesired ? '1' : '0'}&cd=${checkingDisabled ? '1' : '0'}`;
    html += `&tcp=${sendTcp ? '1' : '0'}&ipv6=${sendIpv6 ? '1' : '0'}&edns0=${edns0Enable ? '1' : '0'}&dnssec=${dnssecOk ? '1' : '0'}&udpsize=${escapeHtml(udpSize)}&nsid=${nsidEnable ? '1' : '0'}&mqtype=${escapeHtml(mQType)}`;
    html += `&qmini=${qnameMinimisation ? '1' : '0'}&qposi=${qnamePosition}&qtype=${qnameType}${extraQuery}>${displayData}</a>`;
    return html;
};

const replaceUnknownRrTypeToKnown = (type) => {
    switch (type) {
        case 'UNKNOWN_63': return 'ZONEMD';
        case 'UNKNOWN_64': return 'SVCB';
        case 'UNKNOWN_65': return 'HTTPS';
    }
    return type;
};

const replaceKnownToUnknownRrType = (type) => {
    switch (type) {
        case 'ZONEMD': return 'UNKNOWN_63';
        case 'SVCB': return 'UNKNOWN_64';
        case 'HTTPS': return 'UNKNOWN_65';
    }
    return type;
};

const replaceUnknownRrTypeList = (rrtypes) => {
    return rrtypes.map(item => {
        return replaceUnknownRrTypeToKnown(item);
    });
};

const decodeResourceRecord = (type, msg) => {
    let displayData = '';
    if (type === 'CAA') {
        displayData = `flags: ${msg.flags}, tag: ${msg.tag}, value: ${msg.value}, issuerCritical: ${msg.issuerCritical}`;
    } else if (type === 'DNSKEY') {
        // dns-packet では DNSKEYリソースレコードの Protocol は 3 固定
        displayData = `flags: ${msg.flags}, protocol: 3, algorithm: ${msg.algorithm}, key: ${msg.key.toString('base64')}`;
    } else if (type === 'DS') {
        displayData = `keyTag: ${msg.keyTag}, algorithm: ${msg.algorithm}, digestType: ${msg.digestType}, digest: ${msg.digest.toString('hex').toLowerCase()}`;
    } else if (type === 'NSEC') {
        const rrtypes = replaceUnknownRrTypeList(msg.rrtypes);
        displayData = `nextDomain: ${msg.nextDomain}, rrtypes: ${rrtypes.join(' ')}`;
    } else if (type === 'NSEC3') {
        const rrtypes = replaceUnknownRrTypeList(msg.rrtypes);
        displayData = `algorithm: ${msg.algorithm}, flags: ${msg.flags}, iterations: ${msg.iterations}, salt: ${msg.salt.toString('base64')}, `
        displayData += `nextDomain: ${msg.nextDomain.toString('base64')}, rrtypes: ${rrtypes.join(' ')}`;
    } else if (type === 'RRSIG') {
        const expiration = new Date(msg.expiration * 1000);
        const inception = new Date(msg.inception * 1000);
        displayData = `typeCovered: ${msg.typeCovered}, algorithm: ${msg.algorithm}, labels: ${msg.labels}, originalTTL: ${msg.originalTTL}, expiration: ${expiration.toISOString()}, `;
        displayData += `inception: ${inception.toISOString()}, keyTag: ${msg.keyTag}, signersName: ${msg.signersName}, signature: ${msg.signature.toString('base64')}`;
    } else if (type === 'SOA') {
        displayData = `mname: ${msg.mname}, rname: ${msg.rname}, serial: ${msg.serial}, refresh: ${msg.refresh}, retry: ${msg.retry}, expire: ${msg.expire}, minimum: ${msg.minimum}`;
    } else if (type === 'SRV') {
        displayData = `priority: ${msg.priority}, weight: ${msg.weight}, port: ${msg.port}, target: ${msg.target}`;
    } else if (replaceUnknownRrTypeToKnown(type) === 'SVCB' || replaceUnknownRrTypeToKnown(type) === 'HTTPS' ) {
        let offset = 0;
        const priority = msg.readUInt16BE(offset);
        offset += 2;

        let startOffset = offset;
        const labels = [];
        while (true) {
            const len = msg[startOffset];
            startOffset += 1;
            if (len === 0) break; // ヌルバイトで終了
            const label = msg.toString('utf8', startOffset, startOffset + len);
            labels.push(label);
            startOffset += len;
        }
        const domainName = labels.length === 0 ? '.' : labels.join('.') + '.';

        offset += startOffset - offset;
        let paramString = '';
        while (offset < msg.length) {
            const paramKey = msg.readUInt16BE(offset);
            offset += 2;
            const paramLen = msg.readUInt16BE(offset);
            offset += 2;
            const paramValBuffer = msg.subarray(offset, offset + paramLen);
            offset += paramLen;
            switch (paramKey) {
                case 1: // Additional supported protocols (文字列のリストであり各文字列の前に 1バイトの長さ)
                    const alpnList = [];
                    let idx = 0;
                    while (idx < paramValBuffer.length) {
                        const len = paramValBuffer[idx];
                        idx += 1;
                        alpnList.push(paramValBuffer.toString('utf8', idx, idx + len));
                        idx += len;
                    }
                    paramString += `alpn=${alpnList}, `;
                    break;
                case 3: // Port for alternative endpoint (2バイトの整数)
                    paramString += `port=${paramValBuffer.readUInt16BE(0)}, `;
                    break;
                case 4: // IPv4 address hints (4バイトの整数のリスト)
                    let ipv4List = [];
                    for (let i = 0; i < paramValBuffer.length; i += 4) {
                        const num = paramValBuffer.readUInt32BE(i); 
                        const ipv4str = [
                            (num >>> 24) & 255,
                            (num >>> 16) & 255,
                            (num >>> 8) & 255,
                            num & 255
                        ].join('.');
                        ipv4List.push(ipv4str);
                    }
                    paramString += `ipv4hint=${ipv4List}, `;
                    break;
                case 5: // TLS Encrypted ClientHello Config
                    paramString += `ech=${paramValBuffer.toString('hex')}, `;
                    break;
                case 6: // IPv6 address hints (16バイトの整数のリスト)
                    let ipv6List = [];
                    for (let i = 0; i < paramValBuffer.length; i += 16) {
                        const hex = paramValBuffer.toString('hex', i);
                        const blocks = [];
                        for (let j = 0; j < 16; j += 2) {
                            blocks.push(hex.slice(j * 2, j * 2 + 4));
                        }
                        const ipv6str = compressIPv6(blocks.join(':'));
                        ipv6List.push(ipv6str);
                    }
                    paramString += `ipv6hint=${ipv6List}, `;
                    break;
                case 7: // DNS over HTTPS path template (文字列)
                    paramString += `dohpath=${paramValBuffer.toString('utf8')}, `;
                    break;
                default: // その他は Hexで表示
                    paramString += `other(${paramKey})=${paramValBuffer.toString('hex')}, `;
            }
        }
        if (paramString.length > 2) {
            paramString = paramString.slice(0, -2);
        }
        displayData = `priority: ${priority}, targetName: ${domainName}, params: [ ${paramString} ]`;
    }
    return displayData;
}

const makeHtmlFromDns = (response, bytesRead, origin, pathname, dnsServer, domainName, queryType, queryId, recursionDesired, checkingDisabled,
    sendTcp, sendIpv6, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, qnamePosition, qnameType) => {
    let html = '';
    let questionName = '';
    let questionType = '';

    html += '<div class="result"><h3>--- DNSレスポンス解析結果 ---</h3>';
    html += '<p><strong>基本情報:</strong></p>';
    html += '<ul>';
    html += `<li>応答サイズ: <code>${bytesRead}</code>byte, クエリーID: <code>${queryId} (${response.id === queryId ? '一致' : '不一致'})</code></li>`;
    html += `<li>応答したサーバー: <code>${dnsServer}</code></li>`;

    if (response.questions && response.questions.length > 0) {
        response.questions.forEach((question) => {
            questionName = question.name;
            questionType = replaceUnknownRrTypeToKnown(question.type);
            html += `<li>クエリー名: <code>${questionName}</code></li>`;
            html += `<li>クエリータイプ (type): <code>${questionType}</code></li>`;
        });
    }

    // 応答コード (rcode) の取得
    const rcode = response.rcode;
    html += `<li>応答ステータス (rcode): <code>${escapeHtml(rcode)}</code></li>`;

    // フラグの取得
    let flagString = '';
    if (response.flags & dnsPacket.RECURSION_DESIRED) {
        flagString += 'RD ';
    }
    if (response.flags & dnsPacket.RECURSION_AVAILABLE) {
        flagString += 'RA ';
    }
    if (response.flags & dnsPacket.TRUNCATED_RESPONSE) {
        flagString += 'TC ';
    }
    if (response.flags & dnsPacket.AUTHORITATIVE_ANSWER) {
        flagString += 'AA ';
    }
    if (response.flags & dnsPacket.AUTHENTIC_DATA) {
        flagString += 'AD ';
    }
    if (response.flags & dnsPacket.CHECKING_DISABLED) {
        flagString += 'CD ';
    }
    if (flagString !== '') {
        flagString = flagString.slice(0, -1);
    }
    html += `<li>フラグ (flags): <code>${escapeHtml(flagString)}</code></li>`;
    if (response.flags & dnsPacket.TRUNCATED_RESPONSE) {
        const displayData = addLinkToDisplayData(origin, pathname, dnsServer, domainName, queryType, recursionDesired, checkingDisabled,
            true, sendIpv6, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, qnamePosition, qnameType, 'こちら');
        html += `<ul><li style="color: blue; margin: 0;">TCフラグが立っているので TCPでの再確認を推奨します。${displayData} をクリックしてみてください。</li></ul>`;
    }
    html += '</ul>';

    // Answerセクションについて応答コードに応じた条件分岐
    html += `<p><strong style="color: ${response.answers.length > 0 ? '#dd0000' : '#0000dd'};">ANSWER SECTION (${response.answers.length} 個) :</strong></p>`;
    if (rcode === 'SERVFAIL') {
        html += `<p style="color: red; margin: 0;">SERVFAIL: 応答したサーバー <code>${dnsServer}</code> で一時的なエラーが発生したか、設定に問題があります。</p>`;
        if (recursionDesired && !checkingDisabled) {
            const displayData = addLinkToDisplayData(origin, pathname, dnsServer, domainName, queryType, recursionDesired, true,
                sendTcp, sendIpv6, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, qnamePosition, qnameType, 'こちら');
            html += `<p style="color: orange; margin: 0;">※DNSSEC検証に失敗した可能性があります。${displayData} をクリックしてみてください。</p>`;
        }
    } else if (rcode === 'REFUSED') {
        html += `<p style="color: red; margin: 0;">REFUSED: 応答したサーバー <code>${dnsServer}</code> のポリシーによりクエリーが拒否されました。</p>`;
    } else if (rcode === 'FORMERR') {
        html += `<p style="color: red; margin: 0;">FORMERR: 応答したサーバー <code>${dnsServer}</code> が送信したパケットの形式に問題があると判断しました。</p>`;
    } else if (rcode === 'NXDOMAIN') {
        html += `<p style="color: red; margin: 0;">NXDOMAIN: 問い合わせたドメイン名 <code>${questionName}</code> は存在しませんでした。</p>`;
        if (qnameMinimisation) {
            if (qnamePosition > 0) {
                qnamePosition--;
                const displayData = addLinkToDisplayData(origin, pathname, dnsServer, domainName, queryType, recursionDesired, checkingDisabled,
                    sendTcp, sendIpv6, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, qnamePosition, qnameType, 'こちら');
                if (response.authorities && response.authorities.length > 0) {
                    const soaRr = response.authorities.find(at => at.type === 'SOA');
                    if (soaRr) {
                        if (soaRr.name !== questionName) {
                            html += `<p style="color: red; margin: 0;">※応答したサーバー <code>${dnsServer}</code> が RFC 8020 に対応していないようです。</p>`;
                            html += `<p style="color: orange; margin: 0;">※Empty Non-Terminal かもしれません。${displayData} をクリックしてみてください。</p>`;
                        } else {
                            html += `<p style="color: orange; margin: 0;">※QNAME minimisation が有効になっていますので ${displayData} をクリックしてみてください。</p>`;
                        }
                    }
                }
            }
        }
    } else if (rcode === 'NOERROR') {
        // 正常応答の場合
        if (!response.answers || response.answers.length === 0) {
            // rcodeはNOERRORだが、該当レコードが空 (例: AAAAを引いたがAレコードしか持っていない場合など)
            html += `<p style="color: green; margin: 0;">NOERROR: 指定されたタイプ <code>${questionType}</code> に対するレコード (回答) は見つかりませんでした。</p>`;
            if (qnameMinimisation) {
                if (qnamePosition > 0) {
                    qnamePosition--;
                    const displayData = addLinkToDisplayData(origin, pathname, dnsServer, domainName, queryType, recursionDesired, checkingDisabled,
                        sendTcp, sendIpv6, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, qnamePosition, qnameType, 'こちら');
                    if (response.authorities && response.authorities.length > 0) {
                        const soaRr = response.authorities.find(at => at.type === 'SOA');
                        if (soaRr) {
                            if (soaRr.name !== questionName) {
                                html += `<p style="color: orange; margin: 0;">※Empty Non-Terminal かもしれません。${displayData} をクリックしてみてください。</p>`;
                            } else {
                                html += `<p style="color: orange; margin: 0;">※QNAME minimisation が有効になっていますので ${displayData} をクリックしてみてください。</p>`;
                            }
                        }
                    }
                }
            }
        }
    } else {
        html += `<p style="color: gray; margin: 0;">その他の応答コード: ${escapeHtml(rcode)}</p>`;
    }
    if (response.answers && response.answers.length > 0) {
        html += '<ul>';
        if (qnameMinimisation && qnamePosition > 0) {
            qnamePosition--;
        }
        response.answers.forEach((answer) => {
            let displayData = decodeResourceRecord(answer.type, answer.data);
            if (displayData.length === 0) {
                if (answer.type === 'TXT') {
                    // TXTレコードはBufferまたは'text'の配列か、Bufferか'text'で返ってくる
                    if (Array.isArray(answer.data)) {
                        displayData = escapeHtml(answer.data.map(buf => Buffer.isBuffer(buf) ? buf.toString('utf8') : buf).join(''));
                    } else if (Buffer.isBuffer(answer.data)) {
                        displayData = escapeHtml(answer.data.toString('utf8'));
                    } else {
                        displayData = escapeHtml(answer.data);
                    }
                } else if (answer.type === 'CNAME') {
                    // CNAMEレコードはデータを検索対象ドメイン名として扱い、後続の検索ができるようにする
                    if (queryType === 'PTR-x') {
                        displayData = addLinkToDisplayData(origin, pathname, 'a.root-servers.net', answer.data, 'PTR', false, checkingDisabled,
                            sendTcp, sendIpv6, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, 255, qnameType, answer.data);
                    } else {
                        displayData = addLinkToDisplayData(origin, pathname, 'a.root-servers.net', answer.data, queryType, false, checkingDisabled,
                            sendTcp, sendIpv6, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, 255, qnameType, answer.data);
                    }
                } else if (answer.type === 'NS') {
                    if (qnameMinimisation) {
                        if (answer.name === domainName) {
                            displayData = addLinkToDisplayData(origin, pathname, 'a.root-servers.net', answer.data, 'A', false, checkingDisabled,
                                sendTcp, sendIpv6, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, 255, qnameType, answer.data);
                        } else {
                            displayData = addLinkToDisplayData(origin, pathname, answer.data, domainName, queryType, recursionDesired, checkingDisabled,
                                sendTcp, sendIpv6, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, qnamePosition, qnameType, answer.data);
                        }
                    } else {
                        // NSが、自身の IPアドレスの情報を持っていない場合がある (例： ns014-fc9tjt3ao0p42dr4.f.d-53.info)
                        displayData = addLinkToDisplayData(origin, pathname, 'a.root-servers.net', answer.data, 'A', false, checkingDisabled,
                            sendTcp, sendIpv6, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, 255, qnameType, answer.data);
                    }
                } else if (answer.type === 'MX') {
                    displayData = `preference: ${answer.data.preference}, exchange: `;
                    displayData += addLinkToDisplayData(origin, pathname, 'a.root-servers.net', answer.data.exchange, 'A', false, checkingDisabled,
                        sendTcp, sendIpv6, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, 255, qnameType, answer.data.exchange);
                } else if (answer.type === 'PTR') {
                    displayData = addLinkToDisplayData(origin, pathname, 'a.root-servers.net', answer.data, 'A', false, checkingDisabled,
                        sendTcp, sendIpv6, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, 255, qnameType, answer.data);
                } else if (answer.type === 'A' || answer.type === 'AAAA') {
                    displayData = addLinkToDisplayData(origin, pathname, 'a.root-servers.net', answer.data, 'PTR-x', false, checkingDisabled,
                        sendTcp, sendIpv6, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, 255, qnameType, answer.data);
                } else if (typeof answer.data === 'object') {
                    // オブジェクト構造を持つデータ用
                    displayData = escapeHtml(JSON.stringify(answer.data));
                } else {
                    // Aレコード (文字列のIPアドレス) など通常データ用
                    displayData = escapeHtml(answer.data);
                }
            }
            const answerType = replaceUnknownRrTypeToKnown(escapeHtml(answer.type));
            html += `<li><strong>[${answerType}]</strong> ${escapeHtml(answer.name)} &rarr; <code>${displayData}</code> (TTL: ${parseInt(answer.ttl, 10)}秒)</li>`;
        });
        html += '</ul>';
    }

    // Authorityが返ってきた場合
    html += `<p><strong>AUTHORITY SECTION (${response.authorities.length} 個) :</strong></p>`;
    if (response.authorities && response.authorities.length > 0) {
        html += '<ul>';
        response.authorities.forEach((authorities) => {
            let displayData = decodeResourceRecord(authorities.type, authorities.data);
            if (displayData.length === 0) {
                if (authorities.type === 'NS') {
                    displayData = addLinkToDisplayData(origin, pathname, authorities.data, domainName, queryType, recursionDesired, checkingDisabled,
                        sendTcp, sendIpv6, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, qnamePosition, qnameType, authorities.data);
                } else if (typeof authorities.data === 'object') {
                    // オブジェクト構造を持つデータ用
                    displayData = escapeHtml(JSON.stringify(authorities.data));
                } else {
                    // Aレコード (文字列のIPアドレス) など通常データ用
                    displayData = escapeHtml(authorities.data);
                }
            }
            const authoritiesType = replaceUnknownRrTypeToKnown(escapeHtml(authorities.type));
            html += `<li><strong>[${authoritiesType}]</strong> ${escapeHtml(authorities.name)} &rarr; <code>${displayData}</code> (TTL: ${parseInt(authorities.ttl, 10)}秒)</li>`;
        });
        html += '</ul>';
    } else {
        html += '<p style="color: orange; margin: 0;">権威サーバーの情報は見つかりませんでした。</p>';
    }

    // Additionalが返ってきた場合
    html += `<p><strong>ADDITIONAL SECTION (${response.additionals.length} 個) :</strong></p>`;
    if (response.additionals && response.additionals.length > 0) {
        let optPseudo = '';
        let optError = '';
        html += '<ul>';
        response.additionals.forEach((additionals) => {
            let displayData = decodeResourceRecord(additionals.type, additionals.data);
            if (displayData.length === 0) {
                if (additionals.type === 'A' || additionals.type === 'AAAA') {
                    displayData = addLinkToDisplayData(origin, pathname, additionals.data, domainName, queryType, recursionDesired, checkingDisabled,
                        sendTcp, sendIpv6, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, qnamePosition, qnameType, additionals.data);
                } else if (additionals.type === 'OPT') {
                    if (additionals.name === '.') {
                        // EDNS0
                        const optRecord = additionals;
                        let flagString = '';
                        let nsidString = '';
                        let edeString = '';
                        let mQTypeString = '';
                        if (optRecord.flags & dnsPacket.DNSSEC_OK) {
                            flagString = 'DO';
                        }
                        for (const option of optRecord.options) {
                            if (option.code === 3 && option.data.length > 0) {
                                nsidString = `${option.data.toString('utf-8')} (${option.data.toString('hex')})`;
                            }
                            if (option.code === 15 && Buffer.isBuffer(option.data)) {
                                const buffer = option.data;
                                if (buffer.length < 2) continue;

                                const infoCode = buffer.readUInt16BE(0);
                                const errorName = EDE_ERRORS[infoCode] || 'Unknown Error';
                                edeString = `${infoCode} (${errorName})`;

                                if (buffer.length > 2) {
                                    const extraText = buffer.toString('utf8', 2);
                                    edeString += `: (${extraText})`;
                                }
                            }
                            if (option.code === 21 && Buffer.isBuffer(option.data)) {
                                const buffer = option.data;
                                if (buffer.length < 2) continue;
                                
                                const length  = buffer.readUInt16BE(0);	// Size (in octets) of OPTION-DATA
                                for (let offset = 0; offset < length; offset += 2) {
                                    const type = buffer.readUInt16BE(offset + 2);
                                    mQTypeString += `dnsTypes.toString(type),`;
                                }
                                if (mQTypeString !== '') {
                                    mQTypeString = mQTypeString.slice(0, -1);
                                }
                            }
                        }
                        optPseudo = `<li><strong>[EDNS]</strong> <code>Version: 0, flags: ${flagString}, UDP payload size: ${optRecord.udpPayloadSize}</code></li>`;
                        if (nsidString !== '') {
                            optPseudo += `<li><strong>[NSID]</strong> <code>${nsidString}</code></li>`;
                        }
                        if (edeString !== '') {
                            optPseudo += `<li><strong>[EDE]</strong> <code>${edeString}</code></li>`;
                        }
                        if (mQTypeString !== '') {
                            optPseudo += `<li><strong>[MQTYPE-Response]</strong> <code>${mQTypeString}</code></li>`;
                        }
                    } else {
                        optError = `<p style="color: red; margin: 0;">不明なオプション情報です。(name: ${additionals.name})</p>`;
                    }
                } else if (typeof additionals.data === 'object') {
                    // オブジェクト構造を持つデータ用
                    displayData = escapeHtml(JSON.stringify(additionals.data));
                } else {
                    // 通常データ用
                    displayData = escapeHtml(additionals.data);
                }
            }
            if (additionals.type !== 'OPT') {
                // EDNS0 は下で表示する
                const additionalsType = replaceUnknownRrTypeToKnown(escapeHtml(additionals.type));
                html += `<li><strong>[${additionalsType}]</strong> ${escapeHtml(additionals.name)} &rarr; <code>${displayData}</code> (TTL: ${parseInt(additionals.ttl, 10)}秒)</li>`;
            }
        });
        html += '</ul>';
        if (optPseudo.length > 0) {
            if (response.additionals.length === 1) {
                html += '<p style="color: orange; margin: 0;">追加の情報は見つかりませんでしたがオプション情報が見つかりました。</p>';
            }
            html += `<p><strong>OPT PSEUDOSECTION:</strong></p>`;
            html += `<ul>${optPseudo}</ul>`;
            if (optError.length > 0) {
                html += optError;
            }
        }
    } else {
        html += '<p style="color: orange; margin: 0;">追加の情報は見つかりませんでした。</p>';
    }

    html += '</div>';

    return html;
};

const reverseIPv4 = (ip) => {
    if (typeof ip !== 'string') return '';

    const parts = ip.trim().split('.');
    if (parts.length !== 4) return '';
    if (!parts.every(part => /^\d+$/.test(part))) return '';

    const octets = parts.map(part => Number(part));
    if (octets.some(octet => octet < 0 || octet > 255)) return '';

    return octets.reverse().join('.');
};

const expandIPv6 = (ip) => {
    if (typeof ip !== 'string') return [];

    const normalized = ip.trim().toLowerCase();
    if (!isValidIPv6(normalized)) return [];

    const [leftPart = '', rightPart = ''] = normalized.split('::');
    const left = leftPart ? leftPart.split(':').filter(Boolean) : [];
    const right = rightPart ? rightPart.split(':').filter(Boolean) : [];
    const missing = Math.max(0, 8 - (left.length + right.length));
    const expanded = [...left, ...Array(missing).fill('0'), ...right];

    return expanded.map(part => part.padStart(4, '0'));
};

const reverseIPv6 = (ip) => {
    const expanded = expandIPv6(ip);
    if (expanded.length === 0) return '';

    return expanded
        .join('')
        .split('')
        .reverse()
        .join('.');
};

const compressIPv6 = (ip) => {
    if (typeof ip !== 'string') return '';

    const normalized = ip.trim().toLowerCase();
    if (!isValidIPv6(normalized)) return '';

    const expanded = expandIPv6(normalized);
    const normalizedGroups = expanded.map(part => part.replace(/^0+(?=[0-9a-f])/, '') || '0');

    let bestStart = -1;
    let bestLength = 0;
    let currentStart = -1;
    let currentLength = 0;

    for (let i = 0; i < normalizedGroups.length; i++) {
        if (normalizedGroups[i] === '0') {
            if (currentStart === -1) {
                currentStart = i;
            }
            currentLength += 1;
        } else {
            if (currentLength > bestLength) {
                bestStart = currentStart;
                bestLength = currentLength;
            }
            currentStart = -1;
            currentLength = 0;
        }
    }

    if (currentLength > bestLength) {
        bestStart = currentStart;
        bestLength = currentLength;
    }

    if (bestLength <= 1) {
        return normalizedGroups.join(':');
    }

    const leftCompressed = normalizedGroups.slice(0, bestStart).join(':');
    const rightCompressed = normalizedGroups.slice(bestStart + bestLength).join(':');

    if (leftCompressed && rightCompressed) return `${leftCompressed}::${rightCompressed}`;
    if (leftCompressed) return `${leftCompressed}::`;
    if (rightCompressed) return `::${rightCompressed}`;
    return '::';
};

const isIpv6Loopback = (ip) => {
    if (!isValidIPv6(ip)) {
        return false;
    }

    if (compressIPv6(ip) === '::1') {
        return true;
    }
    return false;
};

const isValidIPv6 = (ip) => {
    if (typeof ip !== 'string') return false;
    return net.isIP(ip.trim()) === 6;
};

const isValidIPv4 = (ip) => {
    if (typeof ip !== 'string') return false;
    return net.isIP(ip.trim()) === 4;
};

const isLoopbackIPv4 = (ip) => {
    if (!isValidIPv4(ip)) return false;
    return Number.parseInt(ip.split('.')[0], 10) === 127;
};

const isPrivateIPv4 = (ip) => {
    if (!isValidIPv4(ip)) return false;

    const [a, b] = ip.split('.').map(Number);
    return a === 10 ||
        (a === 172 && b >= 16 && b <= 31) ||
        (a === 192 && b === 168);
};

const isPrivateIPv6 = (ip) => {
    if (!isValidIPv6(ip)) return false;

    const expanded = expandIPv6(ip);
    if (expanded.length === 0) return false;

    const first = parseInt(expanded[0], 16);
    return (first >= 0xfc00 && first <= 0xfdff) || (first >= 0xfe80 && first <= 0xfebf);
};

const isInvalidDnsServer = (dnsServer) => {
    const value = (dnsServer || '').trim();
    return value === '' ||
        value === 'localhost' ||
        isLoopbackIPv4(value) ||
        isPrivateIPv4(value) ||
        isIpv6Loopback(value) ||
        isPrivateIPv6(value);
};

const isInvalidUdpSize = (udpSize) => {
    const numeric = Number(udpSize);
    return !Number.isInteger(numeric) || numeric < 512 || 65535 < numeric;
};

const isInvalidQueryType = (queryType) => {
    const allowedTypes = ['A', 'AAAA', 'MX', 'NS', 'SOA', 'TXT', 'CNAME', 'DNAME', 'CAA', 'DNSKEY', 'DS', 'NSEC', 'NSEC3', 'RRSIG', 'SRV', 'HTTPS', 'SVCB', 'PTR', 'PTR-x', 'ANY', 'VERSION'];
    return !allowedTypes.includes(queryType);
};

const buildDnsFlags = (recursionDesired, checkingDisabled) => {
    return (recursionDesired ? dnsPacket.RECURSION_DESIRED : 0) |
           (checkingDisabled ? dnsPacket.CHECKING_DISABLED : 0);
};

const server = http.createServer((req, res) => {
    if (req.url === '/favicon.ico') {
        res.writeHead(204);
        res.end();
        return;
    }

    // WHATWG URL API を使用、req.url は相対パスのため第2引数にダミーのベースURLを設定
    const parsedUrl = new URL(req.url, `http://${req.headers.host}/`);
    const params = parsedUrl.searchParams;

    // .get() メソッドでパラメータを取得
    const rawDnsServer = params.get('server') || 'a.root-servers.net';
    const rawDomainName = params.get('name') || '';
    const rawQueryType = params.get('type') || 'A';
    const recursionDesired = params.get('rd') === '1';
    const checkingDisabled = params.get('cd') === '1';
    const qnameMinimisation = params.get('qmini') === '1';
    const rawQnamePosition = params.get('qposi') || '255';
    const rawQnameType = params.get('qtype') || 'A';
    const edns0Enable = params.get('edns0') === '1';
    const dnssecOk = params.get('dnssec') === '1';
    const rawUdpSize = params.get('udpsize') || '1232';
    const nsidEnable = params.get('nsid') === '1';
    const rawMQtype = params.get('mqtype') || '';
    const sendTcp = params.get('tcp') === '1';
    const sendIpv6 = params.get('ipv6') === '1';

    // 画面表示用にすべての入力値をエスケープ (サニタイズ)
    const dnsServer = escapeHtml(rawDnsServer.trim());
    let domainName = escapeHtml(rawDomainName.trim());
    const queryType = escapeHtml(rawQueryType);
    let qnamePosition = escapeHtml(rawQnamePosition.trim());
    const qnameType = escapeHtml(rawQnameType) === 'NS' ? 'NS' : 'A';
    const udpSize = escapeHtml(rawUdpSize.trim());
    const mQType = escapeHtml(rawMQtype.trim());
    const shouldReturnToForm = params.get('back') === '1';
    const shouldKeepSearchVisibleAfterReset = params.get('reset') === '1';
    const shouldShowSearchPanelForError =
        shouldReturnToForm ||
        shouldKeepSearchVisibleAfterReset ||
        isInvalidDnsServer(rawDnsServer) ||
        isInvalidUdpSize(rawUdpSize) ||
        isInvalidQueryType(rawQueryType);

    const resetQMiniHtml = addLinkToDisplayData(parsedUrl.origin, parsedUrl.pathname, 'a.root-servers.net', domainName, queryType, recursionDesired, checkingDisabled,
        sendTcp, sendIpv6, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, '255', qnameType, 'リセット', true, '&reset=1');
    const shouldHideSearchForm = parsedUrl.search !== '' && !shouldKeepSearchVisibleAfterReset && !shouldShowSearchPanelForError;
    const searchToggleState = shouldHideSearchForm ? 'display:none;' : '';

    // HTML (フォーム部分) の構築
    let html = `
        <!DOCTYPE html>
        <html lang="ja">
        <head>
            <meta charset="UTF-8">
            <title>DNSクエリー送信ツール</title>
            <style>
                body { font-family: sans-serif; margin: 0; padding: 20px; background: #f4f6f9; color: #333; }
                .container { max-width: 800px; margin: 0 auto; padding: 25px; background: white; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.05); }
                div { margin-bottom: 10px; }
                .a-button { display: inline-block; padding: 10px 18px; background: rgb(250, 200, 150); color: #5a6472; border: none; border-radius: 8px; font-size: 16px; font-weight: 700; text-decoration: none; letter-spacing: 0.04em; box-shadow: 0 2px 6px rgba(0,0,0,0.12); transition: all 0.15s ease; }
                .a-button:hover { background: rgb(200, 150, 100); transform: translateY(-1px); box-shadow: 0 4px 10px rgba(0,0,0,0.16); }
                label { display: inline-block; font-weight: bold; }
                .label-wide { width: 220px; }
                .label-narrow { width: 194px; }
                input[type="text"], select { padding: 5px; box-sizing: border-box; }
                .input-wide { width: 250px; }
                .input-narrow { width: 60px; }
                input[type="submit"] { padding: 10px 25px; cursor: pointer; background: #007BFF; color: white; border: none; border-radius: 8px; font-size: 16px; font-weight: 700; letter-spacing: 0.04em; box-shadow: 0 2px 6px rgba(0,0,0,0.12); transition: all 0.15s ease; }
                input[type="submit"]:hover { background: #0056b3; transform: translateY(-1px); box-shadow: 0 4px 10px rgba(0,0,0,0.16); }
                #search-toggle { padding: 10px 18px; border: none; border-radius: 8px; color: white; font-size: 16px; font-weight: 700; letter-spacing: 0.04em; cursor: pointer; background: #1F8B4C; box-shadow: 0 2px 6px rgba(0,0,0,0.12); transition: all 0.15s ease; }
                #search-toggle:hover { background: #18733F; transform: translateY(-1px); box-shadow: 0 4px 10px rgba(0,0,0,0.16); }
                #search-toggle[data-state="hide"] { background: #5A6472; }
                #search-toggle[data-state="hide"]:hover { background: #495362; }
                #search-toggle-panel { display: inline-block; padding: 0; border: none; border-radius: 0; background: transparent; box-shadow: none; }
                #search-panel { border: 1px solid #d0d7de; border-radius: 12px; padding: 14px 16px; background: #fafbfc; box-shadow: inset 0 1px 0 rgba(255,255,255,0.7); }
                #search { margin: 0; }
                input[readonly] { background-color: #f0f0f0; border: 1px solid #ccc; }
                .result { padding: 15px; border-radius: 8px; background: #f0f0f0; border-left: 6px solid #007BFF; white-space: pre; overflow-x: scroll; }
                .error { border-color: red; background: #fff0f0; }
                .explanation { font-size: 90%; }
                ul { padding-left: 20px; }
                code { background: #e0e0e0; padding: 2px 5px; border-radius: 4px; font-family: monospace; }
            </style>
        </head>
        <body>
        <div class="container">
            <h2>🔍 <a href=${parsedUrl.origin}${parsedUrl.pathname}>DNSクエリー送信ツール</a></h2>
            <div id="search-panel" style="${searchToggleState}">
                <form id="search" action="search" method="GET" onsubmit="const panel = this.closest('#search-panel'); if (panel) { panel.style.display='none'; } document.getElementById('search-toggle').textContent='入力欄再表示'; document.getElementById('search-toggle').dataset.state='show';">
                    <div>
                        <label for="server" class="label-wide">クエリー先DNSサーバー:</label>
                        <input type="text" class="input-wide" id="server" name="server" value="${dnsServer}" placeholder="a.root-servers.net">
                    </div>
                    <div>
                        <label for="name" class="label-wide">対象ドメイン名 (name):</label>
                        <input type="text" class="input-wide" id="name" name="name" value="${domainName}" placeholder="example.com" autofocus required>
                    </div>
                    <div>
                        <label for="type" class="label-wide">クエリータイプ (type):</label>
                        <select id="type" name="type">
                            <option value="A" ${queryType === 'A' ? 'selected' : ''}>A (IPv4 address)</option>
                            <option value="AAAA" ${queryType === 'AAAA' ? 'selected' : ''}>AAAA (IPv6 address)</option>
                            <option value="MX" ${queryType === 'MX' ? 'selected' : ''}>MX (Mail Exchange)</option>
                            <option value="NS" ${queryType === 'NS' ? 'selected' : ''}>NS (Name Server)</option>
                            <option value="SOA" ${queryType === 'SOA' ? 'selected' : ''}>SOA (Start Of Authority)</option>
                            <option value="TXT" ${queryType === 'TXT' ? 'selected' : ''}>TXT (Text)</option>
                            <option value="CNAME" ${queryType === 'CNAME' ? 'selected' : ''}>CNAME (Canonical Name)</option>
                            <option value="DNAME" ${queryType === 'DNAME' ? 'selected' : ''}>DNAME (Delegation Name)</option>
                            <option value="CAA" ${queryType === 'CAA' ? 'selected' : ''}>CAA (Certification Authority Authorization)</option>
                            <option value="DNSKEY" ${queryType === 'DNSKEY' ? 'selected' : ''}>DNSKEY</option>
                            <option value="DS" ${queryType === 'DS' ? 'selected' : ''}>DS (Delegation Signer)</option>
                            <option value="NSEC" ${queryType === 'NSEC' ? 'selected' : ''}>NSEC (NextSECure record)</option>
                            <option value="NSEC3" ${queryType === 'NSEC3' ? 'selected' : ''}>NSEC3</option>
                            <option value="RRSIG" ${queryType === 'RRSIG' ? 'selected' : ''}>RRSIG (Resource Record Signature)</option>
                            <option value="SRV" ${queryType === 'SRV' ? 'selected' : ''}>SRV (Service)</option>
                            <option value="HTTPS" ${queryType === 'HTTPS' ? 'selected' : ''}>HTTPS</option>
                            <option value="SVCB" ${queryType === 'SVCB' ? 'selected' : ''}>SVCB (Service Binding)</option>
                            <option value="PTR" ${queryType === 'PTR' ? 'selected' : ''}>PTR (Pointer - 4.2.0.192.in-addr.arpa)</option>
                            <option value="PTR-x" ${queryType === 'PTR-x' ? 'selected' : ''}>PTR-x (Pointer - 192.0.2.4)</option>
                            <option value="ANY" ${queryType === 'ANY' ? 'selected' : ''}>ANY</option>
                            <option value="VERSION" ${queryType === 'VERSION' ? 'selected' : ''}>VERSION (CHAOS/TXT/version.bind)</option>
                        </select>
                    </div>
                    <div>
                        <label for="rd" class="label-wide">再帰の要求 (RD):</label>
                        <input type="checkbox" id="rd" name="rd" value="1" ${recursionDesired ? 'checked' : ''}>
                        <label for="rd" style="font-weight:normal; width:auto;">(クエリー先がフルサービスリゾルバーのときはチェック)</label>
                    </div>
                    <div style="background-color: #e0e0ff; margin: 5px 5px 10px 10px; padding: 5px 10px 5px 15px; border: 1px solid #ccc; border-radius: 8px;">
                        <div style="margin: 5px 0px;">
                            <label for="cd" class="label-wide">チェックの無効化 (CD):</label>
                            <input type="checkbox" id="cd" name="cd" value="1" ${checkingDisabled ? 'checked' : ''}>
                            <label for="cd" style="font-weight:normal; width:auto;">(DNSSEC検証を無効化したいときはチェック)</label>
                        </div>
                    </div>
                    <div style="margin-bottom: 5px;">
                        <label for="qmini" class="label-wide">QNAME minimisation:</label>
                        <input type="checkbox" id="qmini" name="qmini" value="1" ${qnameMinimisation ? 'checked' : ''}>
                        <label for="qmini" style="font-weight:normal; width:auto;">(ラベル位置: ${qnamePosition})</label>
                        <input type="text" class="input-narrow" id="qposi" name="qposi" value="${qnamePosition}" hidden>
                    </div>
                    <div style="background-color: #e0e0ff; margin: 5px 5px 10px 10px; padding: 5px 10px 5px 15px; border: 1px solid #ccc; border-radius: 8px;">
                        <div style="margin: 5px 0px;">
                            <label for="qtype" class="label-wide">クエリータイプ:</label>
                            <label style="font-weight:normal; width:auto;"><input type="radio" id="qtype" name="qtype" value="A" ${qnameType === 'A' ? 'checked' : ''}>A/AAAA
                                (<a href="https://datatracker.ietf.org/doc/html/rfc9156" target="_blank">RFC 9156</a>)</label>
                            <label style="font-weight:normal; width:auto;"><input type="radio" id="qtype" name="qtype" value="NS" ${qnameType === 'A' ? '' : 'checked'}>NS
                                (<a href="https://datatracker.ietf.org/doc/html/rfc7816" target="_blank">RFC 7816</a>)</label>
                        </div>
                    </div>
                    <div style="margin-bottom: 5px;">
                        <label for="edns0" class="label-wide">EDNS0の付与:</label>
                        <input type="checkbox" id="edns0" name="edns0" value="1" ${edns0Enable ? 'checked' : ''}>
                        <label for="edns0" style="font-weight:normal; width:auto;">(<a href="https://datatracker.ietf.org/doc/html/rfc6891" target="_blank">RFC 6891</a>)</label>
                    </div>
                    <div style="background-color: #e0e0ff; margin: 5px 5px 10px 10px; padding: 5px 10px 5px 15px; border: 1px solid #ccc; border-radius: 8px;">
                        <div style="margin: 5px 0px;">
                            <label for="dnssec" class="label-wide">DNSSEC情報の要求 (DO):</label>
                            <input type="checkbox" id="dnssec" name="dnssec" value="1" ${dnssecOk ? 'checked' : ''}>
                            <label for="dnssec" style="font-weight:normal; width:auto;">(<a href="https://datatracker.ietf.org/doc/html/rfc3225" target="_blank">RFC 3225</a>)</label>
                        </div>
                        <div style="margin: 5px 0px;">
                            <label for="udpsize" class="label-wide">UDPメッセージサイズ:</label>
                            <input type="text" class="input-narrow" id="udpsize" name="udpsize" value="${udpSize}" placeholder="1232" required>
                            <label for="udpsize" style="font-weight:normal; width:auto;">byte</label>
                        </div>
                        <div style="margin: 5px 0px;">
                            <label for="nsid" class="label-wide">NSIDの要求:</label>
                            <input type="checkbox" id="nsid" name="nsid" value="1" ${nsidEnable ? 'checked' : ''}>
                            <label for="nsid" style="font-weight:normal; width:auto;">(<a href="https://datatracker.ietf.org/doc/html/rfc5001" target="_blank">RFC 5001</a>)</label>
                        </div>
                        <div style="margin: 5px 0px;">
                            <label for="mqtype" class="label-wide">MQTYPE-Query:</label>
                            <input type="text" class="input-wide" id="mqtype" name="mqtype" value="${mQType}" placeholder="AAAA,TXT">
                            <label for="mqtype" style="font-weight:normal; width:auto;">(<a href="https://datatracker.ietf.org/doc/html/rfc10029" target="_blank">RFC 10029</a>)
                            <b><span style="color: red;">※未テスト</span></b></label>
                        </div>
                    </div>
                    <div>
                        <label for="tcp" class="label-wide">TCP送受信:</label>
                        <input type="checkbox" id="tcp" name="tcp" value="1" ${sendTcp ? 'checked' : ''}>
                        <label for="tcp" style="font-weight:normal; width:auto;">(レスポンスに TCフラグが立っていたときはチェック)</label>
                    </div>
                    <div>
                        <label for="ipv6" class="label-wide">IPv6送受信:</label>
                        <input type="checkbox" id="ipv6" name="ipv6" value="1" ${sendIpv6 ? 'checked' : ''}>
                        <label for="ipv6" style="font-weight:normal; width:auto;">(UDP送受信の際に IPv6で接続したいときはチェック)</label>
                    </div>
                    <div style="margin-bottom: 0px;">
                        <input type="submit" value="DNSパケットを送信"> ${resetQMiniHtml}
                    </div>
                </form>
            </div>
            <div id="search-controls" style="margin-top: 15px; margin-bottom: 0px;">
                <div id="search-toggle-panel">
                    <button type="button" id="search-toggle" class="a-button" data-state="${shouldHideSearchForm ? 'show' : 'hide'}" onclick="const panel = document.getElementById('search-panel'); const toggle = document.getElementById('search-toggle'); if (panel.style.display === 'none') { panel.style.display='block'; toggle.textContent='入力欄非表示'; toggle.dataset.state='hide'; } else { panel.style.display='none'; toggle.textContent='入力欄再表示'; toggle.dataset.state='show'; }">${shouldHideSearchForm ? '入力欄再表示' : '入力欄非表示'}</button>
                </div>
            </div>
    `;

    // 初期アクセス時はフォームだけ表示して終了
    if (queryType === 'VERSION') {
        domainName = 'version.bind';
    }
    if (!domainName || !dnsServer) {
        html += `<h3>説明</h3>`
        html += `<div class="explanation">`
        html += `<p>digコマンドや drillコマンドのように DNSクエリーを送信し、受信した内容を表示します。</p>`
        html += `<p>■デフォルトでは<b><a href="https://jprs.jp/glossary/index.php?ID=0158" target="_blank">フルサービスリゾルバー</a></b>の動作 (処理) を<b>体験</b>できるようになっています。`
        html +=   `<ol>`
        html +=     `<li><b>「対象ドメイン名」を入力</b>して<b>「送信」</b>してください。</li>`
        html +=       `<ul>`
        html +=         `<li>AUTHORITYや ADDITIONALの情報に含まれるドメイン名 (NS) や IPアドレス (A, AAAA) をクリックすることで、<a href="https://jprs.jp/glossary/index.php?ID=0152" target="_blank">委任</a>を辿る (非再帰検索/反復検索を体験する) ことができます。</li>`
        html +=       `</ul>`
        html +=     `<li>「クエリー先DNSサーバー」は別の<a href="https://jprs.jp/glossary/index.php?ID=0145">権威サーバー</a>のドメイン名か IPアドレスを入力することもできます。</li>`
        html +=     `<li>「リセット」を押すことで、各種パラメーターを保持しつつ、以下のパラメーターをデフォルト値に戻します。</li>`
        html +=       '<ul>'
        html +=         '<li>「クエリー先DNSサーバー」を「a.root-servers.net」にします。</li>'
        html +=         '<li>QNAME minimisationにおけるドメイン名の位置情報 (どのラベルより後ろを問い合わせているか) をリセットします。</li>'
        html +=       '</ul>'
        html +=   `</ol>`
        html += `</p>`
        html += `<p>■<b><a href="https://jprs.jp/glossary/index.php?ID=0197" target="_blank">スタブリゾルバー</a></b>の動作 (処理) も<b>体験</b>することができます。`
        html +=     `<ol><li>「クエリー先DNSサーバー」に<a href="https://jprs.jp/glossary/index.php?ID=0158" target="_blank">フルサービスリゾルバー</a>のドメイン名か IPアドレスを入力し、</li>`
        html +=         `<li>「対象ドメイン名」を入力して、</li>`
        html +=         `<li>「RDフラグ」にチェックを入れて、</li>`
        html +=         `<li>「送信」してください。</li>`
        html +=         `<ul><li><a href="https://jprs.jp/glossary/index.php?ID=0084" target="_blank">名前解決</a>は入力した<a href="https://jprs.jp/glossary/index.php?ID=0158" target="_blank">フルサービスリゾルバー</a>が代わりにやってくれますので、これ以上の操作は不要です。</li></ul>`
        html +=     `</ol>`
        html += `</p>`
        html += `<p>※DNSSEC検証はしません。</p>`
        html += `</div>`
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(html + '</div></body></html>');
        return;
    }

    // 対象ドメイン名としてURLが渡された場合の変換
    try {
        const urlObj = new URL(domainName);
        if (urlObj && urlObj.hostname) {
            domainName = urlObj.hostname;
        }
    } catch (e) {
    }

    // クエリータイプのホワイトリストチェック
    if (isInvalidQueryType(queryType)) {
        html += `<div class="result error"><p>エラー: 不正なクエリータイプです (${queryType} は不正です)。</p></div>`;
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(html + '</div></body></html>');
        return;
    }

    // 対象DNSサーバーのチェック
    if (isInvalidDnsServer(dnsServer)) {
        html += `<div class="result error"><p>エラー: DNSサーバーを選択し直してください (${dnsServer} は不正です)。</p></div>`;
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(html + '</div></body></html>');
        return;
    }

    // UDP Payload Sizeのチェック
    if (isInvalidUdpSize(udpSize)) {
        html += `<div class="result error"><p>エラー: UDPメッセージサイズを入力し直してください (${udpSize} は不正です)。</p></div>`;
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(html + '</div></body></html>');
        return;
    }

    // DNSクエリーパケットの構築
    let qType = replaceKnownToUnknownRrType(queryType);
    let qClass = 'IN';
    let qName = domainName;
    const qId = Math.floor(Math.random() * 65535);
    if (qName !== '.' && qName.endsWith('.')) {
        qName = qName.slice(0, -1);	// 最後の '.' を削除
    }
    if (queryType === 'VERSION') {
        qType = 'TXT';
        qClass = 'CH';
    } else if (queryType === 'PTR-x') {
        qType = 'PTR';
        if (isValidIPv4(domainName)) {
            qName = `${reverseIPv4(domainName)}.in-addr.arpa`;
        } else if (isValidIPv6(domainName)) {
            qName = `${reverseIPv6(domainName)}.ip6.arpa`;
        } else {
            html += `<div class="result error"><p>エラー: PTR-xクエリーの対象ドメイン名は IPv4か IPv6のアドレスである必要があります。</p></div>`;
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
            res.end(html + '</div></body></html>');
            return;
        }
    }

    if (qnameMinimisation) {
        if (!Number.isInteger(Number(qnamePosition))) {
            html += `<div class="result error"><p>エラー: QNAME minimisationを無効にして試してください。</p></div>`;
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
            res.end(html + '</div></body></html>');
            return;
        }

        let parsedQName = qName.split('.');
        if (qnamePosition < 0 || parsedQName.length <= qnamePosition) {
            qnamePosition = parsedQName.length - 1;
            if (parsedQName[0] === '') {
                // domainName (qName) が '.' の場合、 split() は '.' の両側を '' 文字として配列に格納するため
                // parsedQName.length は 2 になり、qnamePosition は 1 になる
                // ここでは一文字目が '' の場合は qnamePosition を 0 にして、再検索をしないようにする
                qnamePosition = 0;
            }
        }
        if (qnamePosition > 0) {
            // 例えば parsedQName -> [ 'www', 'example', 'com' ] とすると
            // parsedQName.length` は 3 であり qnamePosition は 0 から 2 までの数字になる
            qName = '';
            for (let i = 0; i < parsedQName.length; i++) {
                // もし qnamePosition が 1 の場合、'www' が除去される
                if (i < qnamePosition) {
                    continue;
                }
                qName += `${parsedQName[i]}.`;
            }
            if (qName !== '.' && qName.endsWith('.')) {
                qName = qName.slice(0, -1);	// 最後の '.' を削除
            }
            if ((qnameType === 'A' && qType === 'AAAA') !== true) {
                qType = qnameType;	// RFC 9156 -> A/AAAA, RFC 7816 -> NS
            }
        }
    }
    const dnsFlags = buildDnsFlags(recursionDesired, checkingDisabled);
    let queryPacket = {
        type: 'query',
        id: qId,
        flags: dnsFlags,
        questions: [{
            type: qType,
            class: qClass,
            name: qName
        }]
    };
    if (edns0Enable) {
        const edns0Option = {
            type: 'OPT',
            name: '.',
            udpPayloadSize: udpSize,
            flags: dnssecOk ? dnsPacket.DNSSEC_OK : 0
        };
        if (nsidEnable) {
            const option = { code: 3, data: Buffer.alloc(0) };
            if (typeof edns0Option.options === "undefined") {
                edns0Option.options = new Array();
            }
            edns0Option.options.push(option);
        }
        if (mQType !== '') {
            const mQTypeArray = mQType.split(',');
            const mQlength = mQTypeArray.length * 2;
            const option = { code: 20, length: Buffer.alloc(2), data: Buffer.alloc(mQlength) };
            option.length = mQlength;
            let offset = 0;
            for (const type of mQTypeArray) {
                option.data.writeUInt16BE(dnsTypes.toType(type), offset);
                offset += 2;
            }
            if (typeof edns0Option.options === "undefined") {
                edns0Option.options = new Array();
            }
            edns0Option.options.push(option);
        }
        if (typeof queryPacket.additionals === "undefined") {
            queryPacket.additionals = new Array();
        }
        queryPacket.additionals.push(edns0Option);
    }

    let buf;
    try {
        if (!sendTcp) {
            buf = dnsPacket.encode(queryPacket);
        } else {
            buf = dnsPacket.streamEncode(queryPacket);
        }
    } catch (e) {
        html += `<div class="result error"><p>エラー: 入力されたドメイン名の形式が正しくありません。</p></div>`;
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(html + '</div></body></html>');
        return;
    }

    if (sendTcp) {
        let resultHtml = '';
        let expectedLength = 0
        let receivedBuffer = null

        // TCPソケットを作成して送信
        const tcpClient = new net.Socket();

        tcpClient.connect(53, dnsServer, () => {
            tcpClient.write(buf);
        });

        tcpClient.on('data', data => {
            // TCPの場合、アプリケーションへはいくつかの区切りで転送される (イベントが発生する) ので、受信バッファー (receivedBuffer) は外に確保しておく
            if (receivedBuffer == null) {
                if (data.byteLength > 1) {
                    const plen = data.readUInt16BE(0);
                    expectedLength = plen + 2;	// TCPペイロードの中の DNSメッセージの先頭 2バイトに DNSメッセージのサイズが格納されているので、その分を足す
                    if (plen < 12) {
                        html += `<div class="result" style="border-color:orange;"><p>警告：DNSで期待されるパケットサイズ未満でした: ${plen}</p></div>`;
                    }
                    receivedBuffer = Buffer.from(data);
                }
            } else {
                receivedBuffer = Buffer.concat([receivedBuffer, data]);
            }

            if (receivedBuffer.byteLength >= expectedLength) {
                try {
                    const response = dnsPacket.streamDecode(receivedBuffer);
                    const bytesRead = dnsPacket.streamDecode.bytes;
                    resultHtml += makeHtmlFromDns(response, bytesRead, parsedUrl.origin, parsedUrl.pathname, dnsServer, domainName, queryType, qId, recursionDesired, checkingDisabled,
                        sendTcp, sendIpv6, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, qnamePosition, qnameType);
                } catch (err) {
                    html += `<div class="result error"><p>エラー: パケットの解析に失敗しました: ${escapeHtml(err.message)}</p></div>`;
                } finally {
                    tcpClient.end();	// AWS (Route 53) は、TCPリソース解放をすぐに行う目的で DNSデータの送信後に RSTを送ってくるので、end() では read ECONNRESET が発生してしまうが、あえてこのようにしている
                }
            }
        });

        tcpClient.on('error', (err) => {
            html += `<div class="result error"><p>エラー: TCP通信に失敗しました: ${escapeHtml(err.message)}</p></div>`;
            // このイベントの直後に、'close'イベントが呼び出される
        });

        tcpClient.on('close', (hadError) => {
            if (!hadError || resultHtml !== '') {
                html += resultHtml;
            }
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
            res.end(html + '</div></body></html>');
        });
    } else {
        let isResponded = false;
        var udpClient;

        // UDPソケットを作成して送信
        if (isValidIPv6(dnsServer) || sendIpv6) {
            udpClient = dgram.createSocket('udp6');
        } else {
            udpClient = dgram.createSocket('udp4');
        }

        // タイムアウト処理 (5秒間応答がない場合は通信を打ち切る)
        const timeoutId = setTimeout(() => {
            if (!isResponded) {
                html += `<div class="result error"><p>タイムアウト: サーバー <strong>${dnsServer}</strong> から応答がありませんでした。</p>`;
                if (qnameMinimisation) {
                    const resetQMiniHtml = addLinkToDisplayData(parsedUrl.origin, parsedUrl.pathname, 'a.root-servers.net', domainName, queryType, recursionDesired, checkingDisabled,
                        sendTcp, sendIpv6, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, '255', qnameType, 'こちら');
                    html += `<p>※問い合わせたのは <strong>${qName}</strong> でした。${resetQMiniHtml} で QNAME minimisation の状態をリセットしてみてください。</p>`;
                }
                html += `</div>`;
                res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
                res.end(html + '</div></body></html>');
                udpClient.close();
            }
        }, 5000);

        udpClient.on('message', (msg) => {
            isResponded = true;
            clearTimeout(timeoutId);

            try {
                const response = dnsPacket.decode(msg);
                const bytesRead = dnsPacket.decode.bytes;
                html += makeHtmlFromDns(response, bytesRead, parsedUrl.origin, parsedUrl.pathname, dnsServer, domainName, queryType, qId, recursionDesired, checkingDisabled,
                    sendTcp, sendIpv6, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, qnamePosition, qnameType);
            } catch (err) {
                html += `<div class="result error"><p>エラー: パケットの解析に失敗しました: ${escapeHtml(err.message)}</p></div>`;
            } finally {
                res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
                res.end(html + '</div></body></html>');
                udpClient.close();
            }
        });

        udpClient.on('error', (err) => {
            isResponded = true;
            clearTimeout(timeoutId);
            html += `<div class="result error"><p>エラー: UDP通信に失敗しました: ${escapeHtml(err.message)}</p></div>`;
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
            res.end(html + '</div></body></html>');
            udpClient.close();
        });

        // 指定されたサーバーIPの53番ポートへ送信
        udpClient.send(buf, 0, buf.length, 53, dnsServer, (err) => {
            if (err) {
                isResponded = true;
                clearTimeout(timeoutId);
                html += `<div class="result error"><p>エラー: 送信に失敗しました: ${escapeHtml(err.message)}</p></div>`;
                res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
                res.end(html + '</div></body></html>');
                udpClient.close();
            }
        });
    }
});

const PORT = 3000;
server.listen(PORT, () => {
    console.log(`Webサーバーが起動しました: http://localhost:${PORT}`);
});

server.on('error', (err) => {
    console.error(`Webサーバーエラー: ${err.message}`);
});
