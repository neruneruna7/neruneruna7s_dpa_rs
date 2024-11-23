// const DEBUG_SWITCH1: u8 = 0;

// const CMP_BCC: u8 = 0;
// const CMP_GCC: u8 = 0;

use std::error::Error;

use std::fs::File;
use std::io::{self, BufRead, Write};
use std::sync::{LazyLock, Mutex};

const MAX_SAMPLE: usize = 200 - 1; // 解析に使用する消費電力波形のサンプル数
const START_CNT: usize = 900; // 波形のサンプル点開始点
const END_CNT: usize = 1100; // 波形のサンプル点終了点
const MAX_DPA_COUNT: usize = 5000; // 解析に使用する波形数
const CIPHER_FNAME: &str = "./dpa_aes_set/dpa_tool_zemi_v3/sasebo_aes_ctext_s00_kd0h.txt"; // 既知の暗号文のパス
const KEY_FNAME: &str = "./dpa_aes_set/dpa_tool_zemi_v3/aes_r10_key_test_s00.txt";
const WAVE_SRC_PATH: &str = "./dpa_aes_set/dpa_data_src_d0"; // 解析に使用する波形データのソースパス
const WAVE_DST_PATH: &str = "./dpa_aes_set/dpa_results"; // 解析結果の保存場所

// サイズがデカくてスタックに置けないので，ヒープに置く
static WAVE_SRC: LazyLock<Mutex<Vec<[f64; MAX_SAMPLE]>>> =
    LazyLock::new(|| Mutex::new(vec![[0.0; MAX_SAMPLE]; MAX_DPA_COUNT])); // 消費電力波形
static WAVE_TIME: LazyLock<Mutex<Box<[f64; MAX_SAMPLE]>>> =
    LazyLock::new(|| Mutex::new(Box::new([0.0; MAX_SAMPLE]))); // 時間
static WAVE_GRP0: LazyLock<Mutex<Box<[f64; MAX_SAMPLE]>>> =
    LazyLock::new(|| Mutex::new(Box::new([0.0; MAX_SAMPLE]))); // グループ0の消費電力波形
static WAVE_GRP1: LazyLock<Mutex<Box<[f64; MAX_SAMPLE]>>> =
    LazyLock::new(|| Mutex::new(Box::new([0.0; MAX_SAMPLE]))); // グループ1の消費電力波形
static WAVE_GRP0_AVE: LazyLock<Mutex<Box<[f64; MAX_SAMPLE]>>> =
    LazyLock::new(|| Mutex::new(Box::new([0.0; MAX_SAMPLE]))); // グループ0の平均電力
static WAVE_GRP1_AVE: LazyLock<Mutex<Box<[f64; MAX_SAMPLE]>>> =
    LazyLock::new(|| Mutex::new(Box::new([0.0; MAX_SAMPLE]))); // グループ1の平均電力

// Inverse Sbox
const INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

fn gf_mul_ab(a: u16, b: u16) -> u16 {
    let mut c: u16 = 0;
    for i in (0..8).rev() {
        for k in (0..8).rev() {
            c ^= (((a >> i) & 1) & ((b >> k) & 1)) << (i + k);
        }
    }

    for i in (8..=14).rev() {
        c ^= if (c & (1 << i)) != 0 {
            0x1b << (i - 8)
        } else {
            0
        };
    }
    c & 0xff
}

fn gf_inv_of_a(a: u16) -> u16 {
    let ap2 = gf_mul_ab(a, a);
    let ap3 = gf_mul_ab(ap2, a);
    let ap12 = gf_mul_ab(gf_mul_ab(ap3, ap3), gf_mul_ab(ap3, ap3));
    let ap15 = gf_mul_ab(ap3, ap12);
    let ap60 = gf_mul_ab(gf_mul_ab(ap15, ap15), gf_mul_ab(ap15, ap15));
    let ap240 = gf_mul_ab(gf_mul_ab(ap60, ap60), gf_mul_ab(ap60, ap60));
    let ap14 = gf_mul_ab(ap2, ap12);
    let ap254 = gf_mul_ab(ap240, ap14);

    ap254
}

fn sub_bytes_trans(a: u16) -> u16 {
    let b = gf_inv_of_a(a);
    let mut r = 0;
    let trans = |i: usize| -> u16 {
        if (b & (1 << i)) != 0 {
            1 << i
        } else {
            0
        }
    };
    for i in 0..8 {
        r ^= trans(i);
        r ^= trans((i + 4) % 8);
        r ^= trans((i + 5) % 8);
        r ^= trans((i + 6) % 8);
        r ^= trans((i + 7) % 8);
    }
    r ^= 0x63;
    r
}

fn sub_bytes_trans_state(s: &[[u16; 4]; 4], ssb: &mut [[u16; 4]; 4]) {
    for i in 0..4 {
        for k in 0..4 {
            ssb[i][k] = sub_bytes_trans(s[i][k]);
        }
    }
}

fn inv_sub_bytes_trans(a: u16) -> u16 {
    INV_SBOX[a as usize] as u16
}

fn inv_sub_bytes_trans_state(s: &[[u16; 4]; 4], ssb: &mut [[u16; 4]; 4]) {
    for i in 0..4 {
        for k in 0..4 {
            ssb[i][k] = inv_sub_bytes_trans(s[i][k]);
        }
    }
}

fn shift_rows_trans(s: &[[u16; 4]; 4], ssft: &mut [[u16; 4]; 4]) {
    for i in 0..4 {
        for k in 0..4 {
            ssft[i][k] = s[i][(k + i) % 4];
        }
    }
}

fn inv_shift_rows_trans(s: &[[u16; 4]; 4], ssft: &mut [[u16; 4]; 4]) {
    for i in 0..4 {
        for k in 0..4 {
            ssft[i][k] = s[i][(k + (4 - i)) % 4];
        }
    }
}

fn add_round_key_trans(s: &[[u16; 4]; 4], k: &[u16], sak: &mut [[u16; 4]; 4]) {
    for i in 0..4 {
        sak[0][i] = s[0][i] ^ k[i * 4 + 0];
        sak[1][i] = s[1][i] ^ k[i * 4 + 1];
        sak[2][i] = s[2][i] ^ k[i * 4 + 2];
        sak[3][i] = s[3][i] ^ k[i * 4 + 3];
    }
}

fn evaluate_sf(cipher_text: &[u16], key_w: &[u16]) -> i32 {
    let mut s1 = [[0u16; 4]; 4];
    let mut s2 = [[0u16; 4]; 4];
    let mut s3 = [[0u16; 4]; 4];
    let mut s4 = [[0u16; 4]; 4];

    // Set CipherText to State Array
    for i in 0..4 {
        for j in 0..4 {
            s1[i][j] = cipher_text[i * 4 + j];
        }
    }
    // println!("s1: {:?}", s1);

    // Add Round Key
    add_round_key_trans(&s1, &key_w[10 * 4 * 4..], &mut s2);

    // Round 10
    inv_shift_rows_trans(&s2, &mut s3);
    inv_sub_bytes_trans_state(&s3, &mut s4);

    // Selection Function
    let mut transition_bits = [0; 8];

    let mut transition = |i: usize, a: u16| {
        transition_bits[i] = if (s1[0][0] ^ s4[0][0]) & a != 0 { 1 } else { 0 };
    };
    transition(7, 0x80);
    transition(6, 0x40);
    transition(5, 0x20);
    transition(4, 0x10);
    transition(3, 0x08);
    transition(2, 0x04);
    transition(1, 0x02);
    transition(0, 0x01);
    // println!("transition_bits: {:?}", transition_bits);

    // ハミング距離の計算
    let mut transition_counts = 0;
    for i in 0..8 {
        transition_counts += transition_bits[i];
    }

    // 波形振り分けのためのグループ
    if transition_counts >= 4 {
        1
    } else {
        0
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut key_w = vec![0u16; 176];
    let mut wave_grp0_cnt = 0;
    let mut wave_grp1_cnt = 0;
    let mut wave_grp2_cnt = 0;

    read_wavedata()?;

    let key_file = File::open(KEY_FNAME).expect("[Key] file open error!!");
    let key_lines = io::BufReader::new(key_file).lines();

    // 暗号文を読み込む
    // 1行ごとにバイト列に変換してVecに格納
    let cipher_file = File::open(CIPHER_FNAME).expect("[Cipher Text] file open error!!");
    let cipher_lines = io::BufReader::new(cipher_file).lines();
    let mut cipher_text = Vec::new();
    for (_i, c) in cipher_lines.enumerate() {
        let c = c.expect("Failed to read cipher line");
        let cipher_text_line: Vec<u8> = c
            .split_whitespace()
            .map(|s| u8::from_str_radix(s, 16).expect("Failed to parse cipher byte"))
            .collect();
        cipher_text.push(cipher_text_line);
    }

    println!("Differential power analysis...");
    for (partial_key_no, key_line) in key_lines.enumerate() {
        let key_line = key_line.expect("Failed to read key line");
        let key_bytes: Vec<u8> = key_line
            .split_whitespace()
            .map(|s| u8::from_str_radix(s, 16).expect("Failed to parse key byte"))
            .collect();
        for (i, &byte) in key_bytes.iter().enumerate() {
            key_w[i + 160] = byte as u16;
        }

        init_analyze_var(&mut wave_grp0_cnt, &mut wave_grp1_cnt, &mut wave_grp2_cnt)?;

        // DPAの結果をファイルに出力準備
        let wave_diff_file_name =
            format!("{}/waveDiff_Key{:03}.csv", WAVE_DST_PATH, partial_key_no);
        println!("wavediffilename: {}", wave_diff_file_name);
        let wave_diff_file = File::create(&wave_diff_file_name)
            .expect("[Wave Differential File] file create error!!");
        let mut writer = io::BufWriter::new(wave_diff_file);

        for (dpa_no, cipher_bytes) in cipher_text.iter().enumerate() {
            if dpa_no >= MAX_DPA_COUNT {
                println!("BREAK: dpa_no: {}", dpa_no);
                break;
            }
            let cipher_text: Vec<u16> = cipher_bytes.iter().map(|&b| b as u16).collect();
            // println!("no: {} cipher_text: {:?}", dpa_no, cipher_text);

            // for i in 0..16 {
            //     key_w[i + 160] = key_bytes[i] as u16;
            // }
            // 選択関数によって波形データを振り分けるグループを決定
            let sf_group = evaluate_sf(&cipher_text, &key_w);

            // 選択関数によって波形データを振り分ける
            // インデックスの範囲外アクセス対策で，-1している
            for wave_data_cnt in 0..(END_CNT - START_CNT - 1) {
                if sf_group == 1 {
                    WAVE_GRP1.lock()?[wave_data_cnt] += WAVE_SRC.lock()?[dpa_no][wave_data_cnt];
                } else if sf_group == 0 {
                    WAVE_GRP0.lock()?[wave_data_cnt] += WAVE_SRC.lock()?[dpa_no][wave_data_cnt];
                }
                // println!("wave_src: {}", WAVE_SRC.lock()?[dpa_no][wave_data_cnt]);
                // println!("wave_grp0: {}", WAVE_GRP0.lock()?[wave_data_cnt]);
                // println!("wave_grp1: {}", WAVE_GRP1.lock()?[wave_data_cnt]);

                // println!("wave_src: {}", unsafe { WAVE_SRC[dpa_no][wave_data_cnt] });
            }
            // 各グループの波形数をカウント
            if sf_group == 1 {
                wave_grp1_cnt += 1;
            } else if sf_group == 0 {
                wave_grp0_cnt += 1;
            } else {
                wave_grp2_cnt += 1;
            }
        }
        // println!("wave_grp1: {:?}", WAVE_GRP1.lock()?);

        // インデックスの範囲外アクセス対策で，-1している
        for wave_data_cnt in 0..(END_CNT - START_CNT - 1) {
            // 各グループで平均電力を計算
            let devider = if wave_grp0_cnt != 0 {
                wave_grp0_cnt as f64
            } else {
                1.0
            };
            WAVE_GRP0_AVE.lock()?[wave_data_cnt] = WAVE_GRP0.lock()?[wave_data_cnt] / devider;

            let devider = if wave_grp1_cnt != 0 {
                wave_grp1_cnt as f64
            } else {
                1.0
            };
            WAVE_GRP1_AVE.lock()?[wave_data_cnt] = WAVE_GRP1.lock()?[wave_data_cnt] / devider;

            // 差分電力を計算 ファイルに書き込み
            let left = WAVE_TIME.lock()?[wave_data_cnt] * 1000000.0;
            let right = (WAVE_GRP1_AVE.lock()?[wave_data_cnt]
                - WAVE_GRP0_AVE.lock()?[wave_data_cnt])
                * 1000.0;
            writeln!(writer, "{:.10},{:.15}", left, right)?;
            // println!(
            //     "GR1: {:?}, GR0: {:?}",
            //     WAVE_GRP1_AVE.lock()?[wave_data_cnt],
            //     WAVE_GRP0_AVE.lock()?[wave_data_cnt]
            // );
            // println!("{:.10},{:.15}", left, right);
        }
        writer.flush()?;
        println!("Partial Key No: {:03} finish!", partial_key_no);
    }
    println!("\tfinish!");
    Ok(())
}

fn init_analyze_var(
    wave_grp0_cnt: &mut i32,
    wave_grp1_cnt: &mut i32,
    wave_grp2_cnt: &mut i32,
) -> Result<(), Box<dyn Error>> {
    for _wave_data_cnt in 0..(END_CNT - START_CNT) {
        // indexの範囲外アクセスを起こしている
        // WAVE_GRP0[wave_data_cnt] = 0.0;
        // WAVE_GRP1[wave_data_cnt] = 0.0;
        // WAVE_GRP0_AVE[wave_data_cnt] = 0.0;
        // WAVE_GRP1_AVE[wave_data_cnt] = 0.0;
        // 代替手段としてイテレータを使って初期化する
        WAVE_GRP0.lock()?.iter_mut().for_each(|x| *x = 0.0);
        WAVE_GRP1.lock()?.iter_mut().for_each(|x| *x = 0.0);
        WAVE_GRP0_AVE.lock()?.iter_mut().for_each(|x| *x = 0.0);
        WAVE_GRP1_AVE.lock()?.iter_mut().for_each(|x| *x = 0.0);
    }
    *wave_grp0_cnt = 0;
    *wave_grp1_cnt = 0;
    *wave_grp2_cnt = 0;
    Ok(())
}

fn read_wavedata() -> Result<(), Box<dyn Error>> {
    println!("Read waveform data...");
    for dpa_no in 0..MAX_DPA_COUNT {
        let wave_src_file_name = format!("{}/waveData{}.csv", WAVE_SRC_PATH, dpa_no);
        let wave_src_file =
            File::open(&wave_src_file_name).expect("[Wave Source File] file open error!!");
        println!("wavesrcfilename: {}", wave_src_file_name);
        let wave_src_lines = io::BufReader::new(wave_src_file).lines();

        for (wave_data_cnt, line) in wave_src_lines.enumerate() {
            if wave_data_cnt > START_CNT && wave_data_cnt < END_CNT {
                let line = line.expect("Failed to read line");
                let parts: Vec<&str> = line.split(',').collect();
                // 空白が混じっていてパース失敗するケースがあったのでtrimする
                let wave_time_axis: f64 = parts[0]
                    .trim()
                    .parse()
                    .expect("Failed to parse wave time axis");
                let wave_amplitude: f64 = parts[1]
                    .trim()
                    .parse()
                    .expect("Failed to parse wave amplitude");
                WAVE_SRC.lock()?[dpa_no][wave_data_cnt - START_CNT - 1] = wave_amplitude;
                if dpa_no == 0 {
                    WAVE_TIME.lock()?[wave_data_cnt - START_CNT - 1] = wave_time_axis;
                }
            }
        }
    }
    println!("\tfinish!");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs::File,
        io::{self, BufRead},
    };

    // C実装で出力されたものと，Rust実装で出力されたものが一致するか確認する
    const C_RESULT_PATH: &str = "../dpa_c/dpa_aes_set/dpa_results";
    const RUST_RESULT_PATH: &str = "./dpa_aes_set/dpa_results";

    #[test]
    fn test_result() {
        for i in 0..256 {
            let c_result_path = format!("{}/WaveDiff_Key{:03}.csv", C_RESULT_PATH, i);
            let rust_result_path = format!("{}/waveDiff_Key{:03}.csv", RUST_RESULT_PATH, i);
            let c_result_file = File::open(c_result_path).expect("C result file open error");
            let rust_result_file =
                File::open(rust_result_path).expect("Rust result file open error");
            // ioBuf
            let c_result_lines = io::BufReader::new(c_result_file).lines();
            let rust_result_lines = io::BufReader::new(rust_result_file).lines();
            for (c_line, rust_line) in c_result_lines.zip(rust_result_lines) {
                let c_line = c_line.expect("Failed to read C result line");
                let rust_line = rust_line.expect("Failed to read Rust result line");
                // カンマ区切りで数値に変換して比較
                let c_line: Vec<f64> = c_line
                    .split(',')
                    .map(|s| s.trim().parse().expect("Failed to parse C result line"))
                    .collect();
                let rust_line: Vec<f64> = rust_line
                    .split(',')
                    .map(|s| s.trim().parse().expect("Failed to parse Rust result line"))
                    .collect();
                assert_eq!(c_line, rust_line);
            }
        }
    }
}
