import logging
import os
import pickle
import re

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from .corpus import INITIAL_SCAM_CORPUS, SAFE_CORPUS
from .lexicon import (
    IMPERSONATION_TARGETS,
    RED_FLAG_PHRASES,
    SUSPICIOUS_URL_PATTERNS,
    URGENCY_TRIGGERS,
)

logger = logging.getLogger(__name__)

MODEL_DIR = os.path.join(os.path.dirname(__file__), '..', 'models')
MODEL_FILE = os.path.join(MODEL_DIR, 'sentinel_model.pkl')

RISK_BANDS = [
    ('CRITICAL', 0.72, 1.00),
    ('DANGER', 0.50, 0.72),
    ('SUSPICIOUS', 0.28, 0.50),
    ('SAFE', 0.00, 0.28),
]

WEIGHTS = {
    'similarity': 0.40,
    'urgency': 0.35,
    'red_flag': 0.25,
}

RISK_COLORS = {
    'SAFE': '#00ff88',
    'SUSPICIOUS': '#ffaa00',
    'DANGER': '#ff6600',
    'CRITICAL': '#ff2244',
}

RISK_EMOJI = {
    'SAFE': '✅',
    'SUSPICIOUS': '⚠️',
    'DANGER': '🚨',
    'CRITICAL': '⛔',
}


class PhishingAnalyzer:
    """Explainable four-layer phishing/scam analysis engine."""

    def __init__(self):
        self.vectorizer = None
        self.scam_vectors = None
        self.scam_corpus = list(INITIAL_SCAM_CORPUS)
        self.safe_corpus = list(SAFE_CORPUS)
        self.keyword_weights = dict(URGENCY_TRIGGERS)
        self.model_version = 1
        os.makedirs(MODEL_DIR, exist_ok=True)
        self._load_or_init()

    def _load_or_init(self):
        if os.path.exists(MODEL_FILE):
            try:
                with open(MODEL_FILE, 'rb') as handle:
                    saved = pickle.load(handle)
                self.vectorizer = saved['vectorizer']
                self.scam_vectors = saved['scam_vectors']
                self.scam_corpus = saved['scam_corpus']
                self.keyword_weights = saved['keyword_weights']
                self.model_version = saved.get('model_version', 1)
                return
            except Exception as exc:
                logger.warning("Saved model could not be loaded: %s", exc)
        self._train()

    def _train(self):
        all_corpus = self.scam_corpus + self.safe_corpus
        self.vectorizer = TfidfVectorizer(
            ngram_range=(1, 3),
            max_features=8000,
            stop_words='english',
            lowercase=True,
            sublinear_tf=True,
            min_df=1,
        )
        self.vectorizer.fit(all_corpus)
        self.scam_vectors = self.vectorizer.transform(self.scam_corpus)
        self._save()

    def _save(self):
        with open(MODEL_FILE, 'wb') as handle:
            pickle.dump(
                {
                    'vectorizer': self.vectorizer,
                    'scam_vectors': self.scam_vectors,
                    'scam_corpus': self.scam_corpus,
                    'keyword_weights': self.keyword_weights,
                    'model_version': self.model_version,
                },
                handle,
            )

    def _layer1_similarity(self, message: str) -> dict:
        vector = self.vectorizer.transform([message])
        similarities = cosine_similarity(vector, self.scam_vectors)[0]
        max_similarity = float(np.max(similarities))
        top_index = int(np.argmax(similarities))
        preview = self.scam_corpus[top_index] if max_similarity > 0.05 else None
        amplified = min(max_similarity * 1.6, 1.0)
        return {
            'score': round(amplified, 4),
            'raw_similarity': round(max_similarity, 4),
            'match_confidence': round(max_similarity * 100, 1),
            'top_match_preview': (preview[:120] + '...') if preview else None,
        }

    def _layer2_urgency(self, message: str) -> dict:
        lowered = message.lower()
        triggers = []
        for keyword, weight in self.keyword_weights.items():
            if keyword.lower() in lowered:
                triggers.append(
                    {
                        'keyword': keyword,
                        'weight': round(weight, 3),
                        'danger_level': (
                            'HIGH' if weight >= 0.80 else
                            'MEDIUM' if weight >= 0.60 else 'LOW'
                        ),
                    }
                )
        triggers.sort(key=lambda item: item['weight'], reverse=True)

        impersonated = [
            {'brand': brand.upper(), 'category': category}
            for brand, category in IMPERSONATION_TARGETS.items()
            if brand.lower() in lowered
        ]

        top_three = [item['weight'] for item in triggers[:3]]
        score = min(sum(top_three) / 2.4, 1.0) if top_three else 0.0
        if impersonated and triggers:
            score = min(score * 1.15, 1.0)

        return {
            'score': round(score, 4),
            'triggered_keywords': triggers,
            'trigger_count': len(triggers),
            'impersonated_brands': impersonated,
        }

    def _layer3_red_flags(self, message: str) -> dict:
        lowered = message.lower()
        phrase_hits = [p for p in RED_FLAG_PHRASES if p.lower() in lowered]
        url_flags = []
        for pattern in SUSPICIOUS_URL_PATTERNS:
            url_flags.extend(re.findall(pattern, lowered))

        all_urls = re.findall(
            r'https?://[^\s]+|(?:bit\.ly|tinyurl)\S+',
            message,
            re.IGNORECASE,
        )
        letters = [char for char in message if char.isalpha()]
        caps_ratio = sum(1 for char in letters if char.isupper()) / max(len(letters), 1)
        excessive_caps = caps_ratio > 0.35 and len(message) > 30

        score = min(
            len(phrase_hits) * 0.08
            + len(url_flags) * 0.22
            + len(all_urls) * 0.14
            + (0.18 if excessive_caps else 0.0),
            1.0,
        )
        return {
            'score': round(score, 4),
            'flagged_phrases': phrase_hits[:12],
            'suspicious_urls': list(set(url_flags))[:5],
            'all_urls': all_urls[:5],
            'excessive_caps': excessive_caps,
            'caps_ratio': round(caps_ratio * 100, 1),
        }

    def _layer4_composite(self, l1: dict, l2: dict, l3: dict) -> dict:
        score = round(
            min(
                WEIGHTS['similarity'] * l1['score']
                + WEIGHTS['urgency'] * l2['score']
                + WEIGHTS['red_flag'] * l3['score'],
                1.0,
            ),
            4,
        )
        risk_level = 'SAFE'
        for level, low, high in RISK_BANDS:
            if low <= score <= high:
                risk_level = level
                break

        return {
            'composite_score': score,
            'risk_level': risk_level,
            'color': RISK_COLORS[risk_level],
            'emoji': RISK_EMOJI[risk_level],
        }

    def _generate_recommendation(self, risk: str, l2: dict, l3: dict) -> str:
        brands = [item['brand'] for item in l2['impersonated_brands'][:3]]
        brand_text = f" Impersonation indicators: {', '.join(brands)}." if brands else ''
        link_text = ' Unverified or suspicious link patterns were detected.' if l3['all_urls'] else ''

        messages = {
            'CRITICAL': 'Critical scam indicators detected. Do not click links or provide credentials, OTPs, MPINs, or financial information.',
            'DANGER': 'High-risk phishing indicators detected. Verify the message through the organization’s official app, website, or hotline.',
            'SUSPICIOUS': 'Suspicious characteristics were detected. Avoid unverified links and independently verify the sender before acting.',
            'SAFE': 'No strong scam pattern was detected, but continue to verify unexpected requests through official channels.',
        }
        return messages[risk] + brand_text + link_text

    def analyze(self, message: str) -> dict:
        l1 = self._layer1_similarity(message)
        l2 = self._layer2_urgency(message)
        l3 = self._layer3_red_flags(message)
        l4 = self._layer4_composite(l1, l2, l3)

        return {
            'risk_level': l4['risk_level'],
            'risk_color': l4['color'],
            'risk_emoji': l4['emoji'],
            'composite_score': l4['composite_score'],
            'score_percent': round(l4['composite_score'] * 100, 1),
            'recommendation': self._generate_recommendation(l4['risk_level'], l2, l3),
            'model_version': self.model_version,
            'corpus_size': len(self.scam_corpus),
            'layers': {
                'layer1': {
                    'name': 'Structural Pattern Matching (TF-IDF + Cosine Similarity)',
                    **l1,
                },
                'layer2': {
                    'name': 'Psychological Pressure & Urgency Analysis',
                    **l2,
                },
                'layer3': {
                    'name': 'Red Flag & Malicious Link Detection',
                    **l3,
                },
            },
        }

    def retrain(self, new_scam_samples: list) -> dict | bool:
        existing = set(self.scam_corpus)
        new_samples = []
        for sample in new_scam_samples:
            clean = sample.strip()
            if clean and len(clean) > 20 and clean not in existing:
                self.scam_corpus.append(clean)
                existing.add(clean)
                new_samples.append(clean)

        if not new_samples:
            return False

        previous = {
            'vectorizer': self.vectorizer,
            'scam_vectors': self.scam_vectors,
            'corpus': list(self.scam_corpus[:-len(new_samples)]),
            'weights': dict(self.keyword_weights),
            'version': self.model_version,
        }

        try:
            all_corpus = self.scam_corpus + self.safe_corpus
            self.vectorizer = TfidfVectorizer(
                ngram_range=(1, 3),
                max_features=8000,
                stop_words='english',
                lowercase=True,
                sublinear_tf=True,
                min_df=1,
            )
            self.vectorizer.fit(all_corpus)
            self.scam_vectors = self.vectorizer.transform(self.scam_corpus)

            if not self._validate_retrain(INITIAL_SCAM_CORPUS[:10]):
                raise ValueError('Retrained model did not meet validation threshold')

            self.model_version += 1
            self._save()
            return {
                'added_samples': len(new_samples),
                'new_corpus_size': len(self.scam_corpus),
                'new_version': self.model_version,
                'new_terms': [],
                'keyword_count': len(self.keyword_weights),
            }
        except Exception as exc:
            logger.warning("Retrain rolled back: %s", exc)
            self.vectorizer = previous['vectorizer']
            self.scam_vectors = previous['scam_vectors']
            self.scam_corpus = previous['corpus']
            self.keyword_weights = previous['weights']
            self.model_version = previous['version']
            return False

    def _validate_retrain(self, known_scam_samples: list) -> bool:
        if not known_scam_samples:
            return True
        passed = sum(
            1
            for sample in known_scam_samples
            if self.analyze(sample)['risk_level'] in ('CRITICAL', 'DANGER', 'SUSPICIOUS')
        )
        return passed / len(known_scam_samples) >= 0.60
