# Tổng hợp RC-PAA

## Mục tiêu

RC-PAA là viết tắt của Risk-Calibrated Package Aggregation. Đây là chiến lược mới cho bước Verdict Agent khi đánh giá package PyPI nhiều file trên D2.

Pipeline gốc vẫn giữ nguyên:

1. Extractor Agent lọc file Python cần kiểm tra.
2. Classifier Agent dùng CodeBERT fine-tuned để dự đoán từng file.
3. Verdict Agent tổng hợp kết quả file thành kết quả package.

RC-PAA không train lại model và không thay CodeBERT. Nó chỉ thay cách tổng hợp kết quả file-level thành package-level bằng cách hiểu thêm ngữ cảnh của file.

## Vấn đề của baseline

Baseline VerdictAgent dùng rule bảo thủ:

```text
Nếu bất kỳ file nào bị classify malicious, cả package là malicious.
```

Rule này hợp lý cho malware detection, nhưng trên D2 multi-file có 2 lỗi lớn:

- False Positive cao: file docs, examples, tests, generated code, resource, tooling có thể bị CodeBERT chấm điểm cao, làm cả package benign bị gán malicious.
- False Negative không được cứu: nếu CodeBERT cho score rất thấp trên malware thật, VerdictAgent không có thêm tín hiệu ngữ cảnh để nâng lên.

D2 hiện tại test theo package-level, không phải file-level. File-level labels trong D2 là label package propagate xuống file, nên file-level metric chỉ dùng để debug.

## RC-PAA v1

File code:

```text
src/lamps/agents/risk_calibrated_verdict.py
```

Notebook:

```text
notebooks/evulate_d2_new_stratregies.ipynb
```

Output:

```text
/content/drive/My Drive/NT230/data/d2/results_risk_calibrated/
```

### Ý tưởng

RC-PAA v1 điều chỉnh score của từng file trước khi tổng hợp package:

- Cộng điểm cho file quan trọng như `setup.py`, `__init__.py`, entrypoint.
- Cộng điểm cho file được import bởi file quan trọng.
- Cộng điểm nếu source có hành vi nguy hiểm: `exec`, `eval`, `base64`, subprocess, network, file I/O, credential access.
- Trừ điểm cho docs/examples/tests/tooling.
- Trừ điểm khi CodeBERT score không chắc chắn.
- Trừ điểm nhẹ cho package lớn để giảm FP.

Sau đó package-level verdict dùng max calibrated score:

```text
max(calibrated_file_score) >= threshold => malicious
```

Threshold đang dùng:

```text
0.72
```

### Kết quả v1

Dataset:

```text
n_packages = 518
n_filtered_files = 23440
benign packages = 260
malicious packages = 258
```

| Method | Accuracy | Balanced Accuracy | Precision (malicious) | Recall (malicious) | F1 (malicious) | TN | FP | FN | TP |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Baseline | 0.91699 | 0.91707 | 0.89963 | 0.93798 | 0.91841 | 233 | 27 | 16 | 242 |
| RC-PAA v1 | 0.93050 | 0.93053 | 0.92366 | 0.93798 | 0.93077 | 240 | 20 | 16 | 242 |

### Nhận xét v1

RC-PAA v1 giảm FP từ 27 xuống 20, tức sửa được 7 package benign bị báo nhầm malware.

Recall không đổi:

```text
FN = 16
TP = 242
```

Nghĩa là v1 chủ yếu sửa over-detection, chưa cứu được malware bị CodeBERT bỏ sót.

## Phân tích lỗi sau v1

Sau khi xem wrong predictions, lỗi chính:

- FP còn lại thường có CodeBERT base score rất cao, nhưng file nằm trong docs, generated, resource, tooling, package lớn.
- Import boost quá rộng: `__init__.py` trong package lớn có thể kéo nhiều file lên rủi ro cao.
- Một số benign package lớn như `httpx`, `pandas`, `uvicorn` có nhiều file hợp lệ nhưng chứa hành vi/static token bị model nhầm.
- FN có score gốc rất thấp, nên calibration nhẹ không đủ kéo qua threshold.

Vì vậy v2 tập trung vào:

- Giảm FP mạnh hơn.
- Giữ recall không giảm.
- Thêm rescue nhỏ cho package ít file có hành vi độc rõ.

## RC-PAA v2

File code:

```text
src/lamps/agents/risk_calibrated_verdict.py
```

Class:

```text
RiskCalibratedVerdictAgentV2
```

Notebook:

```text
notebooks/evulate_d2_new_stratregies_v2.ipynb
```

Output:

```text
/content/drive/My Drive/NT230/data/d2/results_risk_calibrated_v2/
```

Commit:

```text
4bafe30 Add risk calibrated D2 strategy v2
```

### Thay đổi v2 so với v1

RC-PAA v2 giữ API của v1, nhưng sửa logic calibration:

1. Import boost chặt hơn

V1 có thể boost file được import bởi `__init__.py`.

V2 chỉ cho import boost từ true entrypoints:

```text
setup.py
__main__.py
install.py
installer.py
post_install.py
build.py
cmdclass install/develop
đường dẫn liên quan setup/install
```

Mục tiêu: tránh việc `__init__.py` trong package lớn làm tăng rủi ro hàng loạt file benign.

2. Giảm bonus cho `__init__.py`

V1 xem `__init__.py` khá quan trọng.

V2 vẫn xem `__init__.py` là tín hiệu cần xem, nhưng bonus nhỏ hơn:

```text
__init__.py bonus = 0.08
setup.py bonus = 0.26
```

3. Phạt nặng hơn docs/examples/tests/tooling

V2 phạt mạnh hơn nếu file nằm trong:

```text
docs/
examples/
tests/
benchmarks/
tutorials/
tooling/
scripts dev
```

Mục tiêu: giảm FP do file minh họa, file test, file phụ trợ.

4. Phạt generated/resource files

V2 thêm generated/resource penalty cho các file có dấu hiệu:

```text
generated
fixtures
resources
tables
coefficients.py
_builtins.py
parser/resources
vendored-meson
valid/invalid test data
```

Mục tiêu: giảm FP trên file dữ liệu sinh sẵn, parser data, fixture, generated code.

5. Large package penalty adaptive

V2 phạt package lớn mạnh hơn nếu file không critical và không được import bởi entrypoint:

```text
n_files >= 50  -> penalty 0.10
n_files >= 100 -> penalty 0.14
n_files >= 250 -> penalty 0.18
n_files >= 500 -> penalty 0.22
```

Mục tiêu: package lớn có nhiều file thì xác suất có 1 file benign bị CodeBERT nhầm cao hơn.

6. Small package behavior rescue

V2 thêm rescue nếu package rất nhỏ và có hành vi độc rõ:

```text
n_files <= 3
behavior_score >= 0.85
file là critical/entrypoint
```

Nếu thỏa, cộng thêm:

```text
small_package_behavior_bonus = 0.28
```

Mục tiêu: malware package nhỏ có payload rõ trong `setup.py` nhưng CodeBERT score thấp vẫn có cơ hội vượt threshold.

## Kết quả v2

Dataset:

```text
n_packages = 518
n_filtered_files = 23440
output = /content/drive/My Drive/NT230/data/d2/results_risk_calibrated_v2
threshold = 0.72
```

| Method | Accuracy | Balanced Accuracy | Precision (malicious) | Recall (malicious) | F1 (malicious) | TN | FP | FN | TP |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Baseline | 0.91699 | 0.91707 | 0.89963 | 0.93798 | 0.91841 | 233 | 27 | 16 | 242 |
| RC-PAA v1 | 0.93050 | 0.93053 | 0.92366 | 0.93798 | 0.93077 | 240 | 20 | 16 | 242 |
| RC-PAA v2 | 0.94788 | 0.94784 | 0.95652 | 0.93798 | 0.94716 | 249 | 11 | 16 | 242 |

### Cải thiện

Baseline -> RC-PAA v2:

```text
Accuracy: 0.91699 -> 0.94788
F1 malicious: 0.91841 -> 0.94716
FP: 27 -> 11
FN: 16 -> 16
```

RC-PAA v1 -> RC-PAA v2:

```text
Accuracy: 0.93050 -> 0.94788
F1 malicious: 0.93077 -> 0.94716
FP: 20 -> 11
FN: 16 -> 16
```

V2 changed:

```text
changed_v2_vs_baseline = 16
changed_v2_vs_v1 = 9
rcpaa_v2_wrong = 27
```

## Kết luận

RC-PAA v2 là bản tốt nhất hiện tại trên D2.

Nó cải thiện mạnh nhất ở precision:

```text
0.89963 baseline -> 0.95652 v2
```

Lý do: v2 giảm false positive của benign package lớn, docs/examples/generated/resource/tooling.

Recall không tăng:

```text
0.93798 cả baseline, v1, v2
```

Lý do: 16 FN có khả năng CodeBERT base score quá thấp hoặc tín hiệu malware nằm ngoài file đã filter/classify. RC-PAA chỉ calibration sau model, không train lại model và không đọc runtime behavior.

## RC-PAA v3

RC-PAA v3 là bản paper-facing. Nó giữ scoring của v2 để không làm lệch kết quả chính, nhưng bổ sung các phần giúp kiến trúc giống document đề xuất hơn.

File code:

```text
src/lamps/agents/risk_calibrated_verdict.py
```

Class:

```text
RiskCalibratedVerdictAgentV3
```

### Thay đổi v3 so với v2

1. Structured output chuẩn

`PackageVerdict` được mở rộng bằng các field optional:

```json
{
  "verdict": "malicious",
  "confidence": 0.89,
  "trigger_file": "utils/helper.py",
  "reason": "Cross-file import from setup.py with high behavioral payload"
}
```

Các field mới:

```text
confidence
trigger_file
reason
structured_outcome
```

Mục tiêu: output của Verdict Agent có thể đưa thẳng cho LLM sinh rationale hoặc đưa vào bảng phân tích lỗi.

2. Optional LLM rationale

V3 hỗ trợ `llm` giống Verdict Agent gốc. Nếu truyền `OllamaClient` hoặc LLM có `generate/run/callable`, V3 sẽ dùng structured outcome để tạo rationale.

Nếu `llm=None`, V3 vẫn chạy deterministic và không gọi network. Đây là chế độ dùng cho metric.

3. Recursive topological import

V2 chỉ boost import trực tiếp từ entrypoint.

V3 thêm import propagation nhiều tầng:

```text
setup.py -> a.py -> b.py -> payload.py
```

Mặc định:

```text
max_import_depth = 3
```

4. Dynamic import literal

V3 bắt thêm import động dạng literal:

```python
__import__("mod")
importlib.import_module("mod")
```

Nếu tên module được tạo bằng biến hoặc nối chuỗi phức tạp, V3 chưa resolve. Phần đó để limitation/future work.

### V3 chưa làm

V3 chưa làm call graph/data flow đầy đủ. Lý do: phần này dễ vượt scope lightweight aggregation và dễ tạo lỗi nếu triển khai nửa vời.

Nên ghi trong paper:

```text
RC-PAA v3 supports recursive static import reachability and literal dynamic imports, but does not implement full call graph or data-flow analysis.
```

## Giới hạn hiện tại

1. Chưa train lại CodeBERT

RC-PAA không sửa representation của model. Nếu CodeBERT không nhận ra payload, RC-PAA chỉ cứu được khi có static behavior rõ.

2. Label D2 là package-level

File-level labels là propagated từ package label, không phải ground truth từng file. Vì vậy không nên tối ưu theo file-level metric.

3. Không có dynamic analysis

RC-PAA chỉ dùng static source code và path context. Nó không bắt được malware chỉ kích hoạt khi install/runtime với điều kiện đặc biệt.

4. Threshold đang fixed

Threshold `0.72` tốt trên D2 hiện tại, nhưng nên validate trên dataset khác trước khi xem là default chung.

## Hướng tiếp theo

1. Phân tích 16 FN của v2

Cần đọc:

```text
rcpaa_v2_wrong_predictions.csv
risk_file_scores_v2.jsonl
```

Mục tiêu: xem FN do CodeBERT score thấp, file bị filter mất, hay malware nằm trong file không có tín hiệu static.

2. Làm threshold sweep chính thức

Notebook đã xuất:

```text
threshold_diagnostic_v2.jsonl
```

Cần chọn threshold theo mục tiêu:

- Nếu ưu tiên bắt malware: hạ threshold, chấp nhận FP cao hơn.
- Nếu ưu tiên giảm báo nhầm benign: giữ hoặc tăng threshold.

3. Thêm package-level feature nhẹ

Có thể thêm các feature không cần train model:

- tỷ lệ file risk cao
- số critical file risk cao
- có install hook không
- có obfuscation trong setup/install path không
- có network/subprocess/base64 chuỗi liên tiếp không

4. Nếu muốn tăng recall thật sự

Cần làm thêm 1 trong các cách:

- fine-tune model với D2 multi-file/file context
- train meta-classifier package-level trên output CodeBERT + static features
- thêm rule detector cho setup.py/install hook
- thêm dynamic/sandbox trace nếu có tài nguyên

## File output quan trọng

Sau khi chạy notebook v2, xem các file:

```text
/content/drive/My Drive/NT230/data/d2/results_risk_calibrated_v2/summary.json
/content/drive/My Drive/NT230/data/d2/results_risk_calibrated_v2/rcpaa_v2_package_report.json
/content/drive/My Drive/NT230/data/d2/results_risk_calibrated_v2/rcpaa_v2_wrong_predictions.csv
/content/drive/My Drive/NT230/data/d2/results_risk_calibrated_v2/rcpaa_v2_changed_vs_baseline.csv
/content/drive/My Drive/NT230/data/d2/results_risk_calibrated_v2/rcpaa_v2_changed_vs_v1.csv
/content/drive/My Drive/NT230/data/d2/results_risk_calibrated_v2/risk_file_scores_v2.jsonl
/content/drive/My Drive/NT230/data/d2/results_risk_calibrated_v2/threshold_diagnostic_v2.jsonl
```
