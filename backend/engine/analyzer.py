# =============================================================
# SENTINEL — Core Analysis Engine (4-Layer Pipeline)
# =============================================================

import re
import pickle
import os
import logging
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from .corpus import INITIAL_SCAM_CORPUS, SAFE_CORPUS
from .lexicon import (
    URGENCY_TRIGGERS,
    IMPERSONATION_TARGETS,
    SUSPICIOUS_URL_PATTERNS,
    RED_FLAG_PHRASES,
)

logger = logging.getLogger(__name__)

MODEL_DIR = os.path.join(os.path.dirname(__file__), '..', 'models')
MODEL_FILE = os.path.join(MODEL_DIR, 'sentinel_model.pkl')

RISK_BANDS = [
    ('CRITICAL',   0.72, 1.00),
    ('DANGER',     0.50, 0.72),
    ('SUSPICIOUS', 0.28, 0.50),
    ('SAFE',       0.00, 0.28),
]

WEIGHTS = {
    'similarity': 0.40,
    'urgency':    0.35,
    'red_flag':   0.25,
}

RISK_COLORS = {'SAFE':'#00ff88','SUSPICIOUS':'#ffaa00','DANGER':'#ff6600','CRITICAL':'#ff2244'}
RISK_EMOJI = {'SAFE':'✅','SUSPICIOUS':'⚠️','DANGER':'🚨','CRITICAL':'⛔'}


class PhishingAnalyzer:
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
                with open(MODEL_FILE, 'rb') as f:
                    saved = pickle.load(f)
                self.vectorizer = saved['vectorizer']
                self.scam_vectors = saved['scam_vectors']
                self.scam_corpus = saved['scam_corpus']
                self.keyword_weights = saved['keyword_weights']
                self.model_version = saved.get('model_version', 1)
                logger.info(f"Model v{self.model_version} loaded. Corpus: {len(self.scam_corpus)} samples.")
            except Exception as e:
                logger.warning(f"Failed to load model: {e}. Reinitializing.")
                self._train()
        else:
            logger.info("No saved model found. Training baseline...")
            self._train()

    def _train(self):
        all_corpus = self.scam_corpus + self.safe_corpus
        self.vectorizer = TfidfVectorizer(ngram_range=(1,3),max_features=8000,stop_words='english',lowercase=True,sublinear_tf=True,min_df=1)
        self.vectorizer.fit(all_corpus)
        self.scam_vectors = self.vectorizer.transform(self.scam_corpus)
        self._save()
        logger.info(f"Model trained. Corpus: {len(self.scam_corpus)} scam / {len(self.safe_corpus)} safe samples.")

    def _save(self):
        with open(MODEL_FILE, 'wb') as f:
            pickle.dump({'vectorizer':self.vectorizer,'scam_vectors':self.scam_vectors,'scam_corpus':self.scam_corpus,'keyword_weights':self.keyword_weights,'model_version':self.model_version}, f)
        logger.info(f"Model v{self.model_version} saved.")

    def _layer1_similarity(self, message: str) -> dict:
        msg_vec = self.vectorizer.transform([message])
        sims = cosine_similarity(msg_vec, self.scam_vectors)[0]
        max_sim = float(np.max(sims))
        top_idx = int(np.argmax(sims))
        top_text = self.scam_corpus[top_idx] if max_sim > 0.05 else None
        amplified = min(max_sim * 1.6, 1.0)
        return {'score':round(amplified,4),'raw_similarity':round(max_sim,4),'top_match_preview':(top_text[:120]+'...') if top_text else None,'match_confidence':round(float(sims[top_idx])*100,1)}

    def _layer2_urgency(self, message: str) -> dict:
        msg_lower = message.lower()
        triggers = []
        for kw,w in self.keyword_weights.items():
            if kw.lower() in msg_lower:
                triggers.append({'keyword':kw,'weight':round(w,3),'danger_level':'HIGH' if w>=0.80 else 'MEDIUM' if w>=0.60 else 'LOW'})
        triggers.sort(key=lambda x:x['weight'],reverse=True)
        impersonated=[]
        for brand,category in IMPERSONATION_TARGETS.items():
            if brand.lower() in msg_lower:
                impersonated.append({'brand':brand.upper(),'category':category})
        top3=[t['weight'] for t in triggers[:3]]
        urgency_score=min(sum(top3)/2.4,1.0) if top3 else 0.0
        if impersonated and triggers:
            urgency_score=min(urgency_score*1.15,1.0)
        return {'score':round(urgency_score,4),'triggered_keywords':triggers,'trigger_count':len(triggers),'impersonated_brands':impersonated}

    def _layer3_red_flags(self, message: str) -> dict:
        msg_lower=message.lower(); phrase_hits=[]; url_flags=[]
        for phrase in RED_FLAG_PHRASES:
            if phrase.lower() in msg_lower: phrase_hits.append(phrase)
        for pattern in SUSPICIOUS_URL_PATTERNS:
            url_flags.extend(re.findall(pattern,msg_lower))
        all_urls=re.findall(r'https?://[^\s]+|(?:bit\.ly|tinyurl)\S+',message,re.IGNORECASE)
        letters=[c for c in message if c.isalpha()]
        caps_ratio=sum(1 for c in letters if c.isupper())/max(len(letters),1)
        excessive_caps=caps_ratio>0.35 and len(message)>30
        score=min((len(phrase_hits)*0.08)+(len(url_flags)*0.22)+(len(all_urls)*0.14)+(0.18 if excessive_caps else 0.0),1.0)
        return {'score':round(score,4),'flagged_phrases':phrase_hits[:12],'suspicious_urls':list(set(url_flags))[:5],'all_urls':all_urls[:5],'excessive_caps':excessive_caps,'caps_ratio':round(caps_ratio*100,1)}

    def _layer4_composite(self,l1:dict,l2:dict,l3:dict)->dict:
        score=round(min(WEIGHTS['similarity']*l1['score']+WEIGHTS['urgency']*l2['score']+WEIGHTS['red_flag']*l3['score'],1.0),4)
        risk_level='SAFE'
        for level,low,high in RISK_BANDS:
            if low<=score<=high:
                risk_level=level; break
        return {'composite_score':score,'risk_level':risk_level,'color':RISK_COLORS[risk_level],'emoji':RISK_EMOJI[risk_level],'score_breakdown':{'similarity_contribution':round(WEIGHTS['similarity']*l1['score'],4),'urgency_contribution':round(WEIGHTS['urgency']*l2['score'],4),'red_flag_contribution':round(WEIGHTS['red_flag']*l3['score'],4)}}

    def _generate_recommendation(self,risk:str,l1:dict,l2:dict,l3:dict)->str:
        top_kw=[t['keyword'] for t in l2['triggered_keywords'][:3]]; brands=[b['brand'] for b in l2['impersonated_brands'][:3]]; urls=l3['all_urls'][:2]; sim_pct=round(l1['raw_similarity']*100,1)
        brand_str=f", impersonating {', '.join(brands)}" if brands else ""; kw_str=f" Psychological pressure tactics detected: {top_kw}." if top_kw else ""; url_str=f" Malicious links found: {urls}." if urls else ""
        if risk=='CRITICAL': return f"SCAM CONFIRMED. This message{brand_str} has {sim_pct}% structural similarity to known phishing templates in our Philippine scam database.{kw_str}{url_str} DO NOT click any links. DO NOT share your OTP, MPIN, card number, or personal information. DELETE this message immediately. Report to the PNP Anti-Cybercrime Group at acg.pnp.gov.ph or call 0966-837-5483."
        if risk=='DANGER': return f"HIGH RISK DETECTED. This message{brand_str} contains multiple red flags consistent with phishing and smishing attacks.{kw_str}{url_str} Do NOT respond, click any links, or provide any personal information. Contact the legitimate organization directly via their official hotline or app to verify."
        if risk=='SUSPICIOUS': return f"SUSPICIOUS MESSAGE. This message shows characteristics commonly found in scam attempts.{kw_str} Exercise extreme caution. Do NOT click unverified links or provide personal data. Cross-check with the sender's official website or call center before taking any action."
        return "LOW RISK. This message does not closely match known scam patterns in our database. No high-risk psychological pressure tactics were detected. Stay vigilant — when in doubt, always verify through the official app or website of the organization before acting on any message."

    def analyze(self,message:str)->dict:
        l1=self._layer1_similarity(message); l2=self._layer2_urgency(message); l3=self._layer3_red_flags(message); l4=self._layer4_composite(l1,l2,l3)
        return {'risk_level':l4['risk_level'],'risk_color':l4['color'],'risk_emoji':l4['emoji'],'composite_score':l4['composite_score'],'score_percent':round(l4['composite_score']*100,1),'recommendation':self._generate_recommendation(l4['risk_level'],l1,l2,l3),'model_version':self.model_version,'corpus_size':len(self.scam_corpus),'layers':{'layer1':{'name':'Structural Pattern Matching (TF-IDF + Cosine Similarity)','score':l1['score'],'score_percent':round(l1['score']*100,1),'raw_similarity':l1['raw_similarity'],'match_confidence':l1['match_confidence'],'top_match_preview':l1['top_match_preview'],'contribution':l4['score_breakdown']['similarity_contribution']},'layer2':{'name':'Psychological Pressure & Urgency Analysis','score':l2['score'],'score_percent':round(l2['score']*100,1),'triggered_keywords':l2['triggered_keywords'],'trigger_count':l2['trigger_count'],'impersonated_brands':l2['impersonated_brands'],'contribution':l4['score_breakdown']['urgency_contribution']},'layer3':{'name':'Red Flag & Malicious Link Detection','score':l3['score'],'score_percent':round(l3['score']*100,1),'flagged_phrases':l3['flagged_phrases'],'suspicious_urls':l3['suspicious_urls'],'all_urls':l3['all_urls'],'excessive_caps':l3['excessive_caps'],'contribution':l4['score_breakdown']['red_flag_contribution']}}}

    def retrain(self,new_scam_samples:list)->dict|bool:
        if not new_scam_samples: return False
        existing=set(self.scam_corpus); added=0; truly_new_samples=[]
        for sample in new_scam_samples:
            clean=sample.strip()
            if clean and clean not in existing and len(clean)>20:
                self.scam_corpus.append(clean); existing.add(clean); truly_new_samples.append(clean); added+=1
        if added==0:
            logger.info("Retrain skipped: all submitted samples already exist in corpus."); return False
        logger.info(f"Retraining: {added} new samples added. Total corpus: {len(self.scam_corpus)}")
        prev_vectorizer=self.vectorizer; prev_scam_vectors=self.scam_vectors; prev_scam_corpus=list(self.scam_corpus); prev_kw_weights=dict(self.keyword_weights); prev_version=self.model_version
        try:
            all_corpus=self.scam_corpus+self.safe_corpus
            new_vectorizer=TfidfVectorizer(ngram_range=(1,3),max_features=8000,stop_words='english',lowercase=True,sublinear_tf=True,min_df=1)
            new_vectorizer.fit(all_corpus); new_scam_vectors=new_vectorizer.transform(self.scam_corpus); self.vectorizer=new_vectorizer; self.scam_vectors=new_scam_vectors
            self._recalibrate_weights(truly_new_samples); new_terms=self._discover_triggers()
            validation_set=list(INITIAL_SCAM_CORPUS)[:10]
            if not self._validate_retrain(validation_set):
                self.vectorizer=prev_vectorizer; self.scam_vectors=prev_scam_vectors; self.scam_corpus=prev_scam_corpus; self.keyword_weights=prev_kw_weights; self.model_version=prev_version
                logger.warning("Retrain rolled back. Model remains at v%d.",prev_version); return False
            self.model_version+=1; self._save()
            logger.info(f"Retrain COMPLETE → v{self.model_version} | Corpus: {len(self.scam_corpus)} | Keywords: {len(self.keyword_weights)} | New triggers: {new_terms[:5]}")
            return {'added_samples':added,'new_corpus_size':len(self.scam_corpus),'new_version':self.model_version,'new_terms':new_terms[:10],'keyword_count':len(self.keyword_weights)}
        except Exception as e:
            logger.error(f"Retrain FAILED: {e}. Rolling back.",exc_info=True); self.vectorizer=prev_vectorizer; self.scam_vectors=prev_scam_vectors; self.scam_corpus=prev_scam_corpus; self.keyword_weights=prev_kw_weights; self.model_version=prev_version; return False

    def _recalibrate_weights(self,new_samples:list):
        total=max(len(new_samples),1)
        for kw in list(self.keyword_weights.keys()):
            kw_lower=kw.lower(); hits=sum(1 for text in new_samples if kw_lower in text.lower()); freq_ratio=hits/total
            if freq_ratio>0:
                original=self.keyword_weights[kw]; data_driven=min(freq_ratio*3.0,1.0); self.keyword_weights[kw]=round(0.65*original+0.35*data_driven,3)

    def _discover_triggers(self)->list:
        NOISE_WORDS={'your','will','have','this','that','with','from','been','please','dear','hello','thank','regards','note','notice','message','text','email','number','time','date','today','here','there','when','then','also','into','over','more'}
        feature_names=self.vectorizer.get_feature_names_out(); tfidf_matrix=self.scam_vectors.toarray(); mean_scores=np.mean(tfidf_matrix,axis=0); doc_freq=np.sum(tfidf_matrix>0,axis=0); min_doc_freq=max(2,len(self.scam_corpus)//20); top_indices=np.argsort(mean_scores)[-120:]
        new_terms=[]
        for i in top_indices:
            term=feature_names[i]; score=mean_scores[i]; df=int(doc_freq[i])
            if score<0.035 or len(term)<4 or term in self.keyword_weights or term in NOISE_WORDS or df<min_doc_freq: continue
            danger_weight=round(min(score*5.0,0.75),3); self.keyword_weights[term]=danger_weight; new_terms.append(term); logger.info(f"New trigger discovered: '{term}' (score={score:.4f}, df={df}, weight={danger_weight})")
        return new_terms

    def _validate_retrain(self,known_scam_samples:list)->bool:
        if not known_scam_samples: return True
        test_set=known_scam_samples[:10]; passed=0
        for sample in test_set:
            if self.analyze(sample)['risk_level'] in ('CRITICAL','DANGER','SUSPICIOUS'): passed+=1
        pass_rate=passed/len(test_set); logger.info(f"Retrain validation: {passed}/{len(test_set)} known scams correctly flagged ({pass_rate:.0%})")
        if pass_rate<0.60:
            logger.warning(f"Retrain FAILED validation ({pass_rate:.0%} < 60% threshold). New model rejected. Keeping previous version."); return False
        return True
