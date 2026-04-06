"""
CTID Technique Inference Engine (TIE) integration.

Loads a technique–technique scoring matrix from disk and ranks gap techniques
by max conditional score vs observed techniques.

Supported file formats (TIE_MODEL_PATH):
  - JSON: nested dict { "T1059.001": { "T1071.001": 0.82, ... }, ... }
  - CSV: square matrix (row index + column headers = technique IDs)
  - Pickle: dict (nested as above) or pandas.DataFrame matrix

Source: https://github.com/center-for-threat-informed-defense/technique-inference-engine
"""
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class TIERanker:
    def __init__(self, tie_model_path: Optional[str] = None, silent: bool = False):
        # None → TIE_MODEL_PATH env; explicit "" → no model (tests / override)
        if tie_model_path is not None:
            model_path = str(tie_model_path).strip()
        else:
            model_path = os.getenv("TIE_MODEL_PATH", "").strip()
        self.model: Optional[Dict[str, Dict[str, float]]] = None
        if model_path:
            self.model = self._load_model(model_path)
        if self.model is None and not silent:
            hint = (
                "Set TIE_MODEL_PATH in .env to a JSON/CSV/pickle matrix "
                "(nested dict T_obs → T_gap → float)."
            )
            if model_path:
                print(f"    [TIE] No usable model from {model_path!r} — gaps ranked A–Z (score=0.0).\n          {hint}")
            else:
                print(
                    "    [TIE] No model loaded -- gaps will be ranked alphabetically (score=0.0).\n"
                    f"          {hint}"
                )

    def _load_model(self, path: str) -> Optional[Dict[str, Dict[str, float]]]:
        from config import BASE_DIR

        p = Path(path).expanduser()
        if not p.is_file():
            alt = (BASE_DIR / path).expanduser()
            if alt.is_file():
                p = alt
        if not p.is_file():
            return None
        suf = p.suffix.lower()
        try:
            if suf in (".pkl", ".pickle"):
                import pickle

                with p.open("rb") as fh:
                    obj = pickle.load(fh)
                return self._normalize_model(obj)
            if suf == ".csv":
                import pandas as pd

                df = pd.read_csv(p, index_col=0)
                return self._dataframe_to_nested(df)
            if suf == ".json":
                raw = json.loads(p.read_text(encoding="utf-8"))
                return self._normalize_model(raw)
        except Exception as exc:
            print(f"    [TIE] Error loading {path}: {exc}")
        return None

    def _dataframe_to_nested(self, df) -> Dict[str, Dict[str, float]]:
        out: Dict[str, Dict[str, float]] = {}
        for row_id in df.index:
            rid = str(row_id).strip().upper()
            out[rid] = {}
            for col in df.columns:
                cid = str(col).strip().upper()
                val = df.loc[row_id, col]
                try:
                    f = float(val)
                except (TypeError, ValueError):
                    continue
                out[rid][cid] = f
        return out

    def _normalize_model(self, obj: Any) -> Optional[Dict[str, Dict[str, float]]]:
        if obj is None:
            return None
        if isinstance(obj, dict) and not obj:
            return None
        try:
            import pandas as pd

            if isinstance(obj, pd.DataFrame):
                return self._dataframe_to_nested(obj)
        except Exception:
            pass
        if isinstance(obj, dict) and "matrix" in obj:
            return self._normalize_model(obj["matrix"])
        if not isinstance(obj, dict):
            return None
        # Top-level keys should be technique IDs; values are dicts of technique -> float
        sample = next(iter(obj.values()), None)
        if sample is not None and isinstance(sample, dict):
            nested: Dict[str, Dict[str, float]] = {}
            for k, v in obj.items():
                if not isinstance(v, dict):
                    return None
                row: Dict[str, float] = {}
                for k2, val in v.items():
                    try:
                        row[str(k2).strip().upper()] = float(val)
                    except (TypeError, ValueError):
                        continue
                nested[str(k).strip().upper()] = row
            return nested or None
        return None

    def _get_directed(self, row_key: str, col_key: str) -> float:
        if not self.model:
            return 0.0
        rk = None
        for k in self.model:
            if str(k).upper() == row_key.upper():
                rk = k
                break
        if rk is None:
            return 0.0
        row = self.model[rk]
        for k2, val in row.items():
            if str(k2).upper() == col_key.upper():
                try:
                    return float(val)
                except (TypeError, ValueError):
                    return 0.0
        return 0.0

    def _cell(self, obs: str, gap: str) -> float:
        return max(
            self._get_directed(obs, gap),
            self._get_directed(gap, obs),
        )

    def rank_gaps(
        self,
        observed_techniques: List[str],
        gap_techniques: List[str],
        top_n: int = 20,
    ) -> List[Tuple[str, float]]:
        if self.model is None:
            ranked = sorted(gap_techniques)
            return [(t, 0.0) for t in ranked[:top_n]]

        obs_set = {str(x).strip().upper() for x in observed_techniques if x}
        scores: Dict[str, float] = {}
        for gap in gap_techniques:
            g = str(gap).strip().upper()
            best = 0.0
            for obs in obs_set:
                best = max(best, self._cell(obs, g))
            scores[g] = best

        ranked_pairs = sorted(scores.items(), key=lambda x: (-x[1], x[0]))
        if all(s == 0.0 for _, s in ranked_pairs):
            ranked_pairs = [(t, 0.0) for t in sorted(gap_techniques)[:top_n]]
        else:
            ranked_pairs = ranked_pairs[:top_n]
        return ranked_pairs
