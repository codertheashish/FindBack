import re
from datetime import datetime
from typing import Dict, Any, List, Tuple

STOPWORDS = {
    'a', 'an', 'the', 'in', 'on', 'at', 'by', 'for', 'with', 'about', 'against',
    'between', 'into', 'through', 'during', 'before', 'after', 'above', 'below',
    'to', 'from', 'up', 'down', 'of', 'off', 'over', 'under', 'again', 'further',
    'then', 'once', 'here', 'there', 'when', 'where', 'why', 'how', 'all', 'any',
    'both', 'each', 'few', 'more', 'most', 'other', 'some', 'such', 'no', 'nor',
    'not', 'only', 'own', 'same', 'so', 'than', 'too', 'very', 's', 't', 'can',
    'will', 'just', 'don', 'should', 'now', 'i', 'my', 'me', 'it', 'its', 'was',
    'is', 'found', 'lost', 'item', 'has', 'have', 'had', 'left', 'near'
}

CATEGORY_SYNONYMS = {
    'electronics': {'electronics', 'gadgets', 'tech', 'laptop', 'phone', 'device', 'audio', 'accessories'},
    'wallets & bags': {'wallets & bags', 'wallet', 'purse', 'bag', 'backpack', 'pouch', 'accessories'},
    'id & cards': {'id & cards', 'id card', 'cards', 'license', 'badge', 'pass', 'keys & id'},
    'keys': {'keys', 'keychain', 'car key', 'fob', 'keys & id'},
    'clothing & apparel': {'clothing & apparel', 'clothing', 'jacket', 'coat', 'hoodie', 'hat', 'scarf', 'apparel'},
    'books & stationery': {'books & stationery', 'book', 'notebook', 'stationery', 'binder', 'pen', 'calculator'},
    'jewelry & watches': {'jewelry & watches', 'watch', 'jewelry', 'ring', 'necklace', 'bracelet', 'smartwatch'},
    'bottles & flasks': {'bottles & flasks', 'water bottle', 'flask', 'bottle', 'mug', 'tumbler'},
    'other': {'other', 'miscellaneous', 'misc'}
}

def clean_text(text: str) -> str:
    if not text:
        return ""
    text = text.lower()
    text = re.sub(r'[^a-z0-9\s]', ' ', text)
    return ' '.join(text.split())

def get_tokens(text: str) -> set:
    words = clean_text(text).split()
    return {w for w in words if w not in STOPWORDS and len(w) > 1}

def token_similarity(tokens1: set, tokens2: set) -> float:
    if not tokens1 or not tokens2:
        return 0.0
    intersection = tokens1.intersection(tokens2)
    union = tokens1.union(tokens2)
    return len(intersection) / len(union)

def calculate_category_score(cat1: str, cat2: str) -> Tuple[float, str]:
    c1 = (cat1 or '').strip().lower()
    c2 = (cat2 or '').strip().lower()

    if not c1 or not c2:
        return 0.0, "Missing category"
    
    if c1 == c2:
        return 1.0, f"Exact category match: '{cat1}'"
    
    # Check synonymous groups
    for group in CATEGORY_SYNONYMS.values():
        if c1 in group and c2 in group:
            return 0.7, f"Related category cluster match: '{cat1}' ~ '{cat2}'"
            
    return 0.0, f"Different categories: '{cat1}' vs '{cat2}'"

def calculate_location_score(loc1: str, loc2: str) -> Tuple[float, str, set]:
    l1 = clean_text(loc1)
    l2 = clean_text(loc2)
    
    if not l1 or not l2:
        return 0.1, "No location data provided", set()
    
    t1 = get_tokens(l1)
    t2 = get_tokens(l2)
    common = t1.intersection(t2)
    
    if l1 == l2:
        return 1.0, f"Identical location reported: '{loc1}'", common
    
    # Check substring inclusion
    if l1 in l2 or l2 in l1:
        return 0.85, f"Location substring match: '{loc1}' and '{loc2}'", common or {l1, l2}
    
    if common:
        sim = token_similarity(t1, t2)
        score = min(1.0, max(0.4, sim * 1.5))
        return score, f"Shared location landmarks: {', '.join(sorted(common))}", common
        
    return 0.05, f"Different locations ('{loc1}' vs '{loc2}')", set()

def calculate_date_score(date_str1: str, date_str2: str) -> Tuple[float, str]:
    formats = ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"]
    d1 = None
    d2 = None
    
    for fmt in formats:
        try:
            d1 = datetime.strptime(date_str1.split('.')[0], fmt)
            break
        except Exception:
            pass
            
    for fmt in formats:
        try:
            d2 = datetime.strptime(date_str2.split('.')[0], fmt)
            break
        except Exception:
            pass
            
    if not d1 or not d2:
        return 0.4, "Date format could not be strictly parsed"
        
    delta_days = abs((d1 - d2).days)
    
    if delta_days == 0:
        return 1.0, "Same day report (0 days difference)"
    elif delta_days == 1:
        return 0.9, "1 day apart"
    elif delta_days <= 3:
        return 0.75, f"Within 3 days ({delta_days} days apart)"
    elif delta_days <= 7:
        return 0.55, f"Within 1 week ({delta_days} days apart)"
    elif delta_days <= 14:
        return 0.35, f"Within 2 weeks ({delta_days} days apart)"
    elif delta_days <= 30:
        return 0.2, f"{delta_days} days apart"
    else:
        return 0.05, f"{delta_days} days apart (distant timeline)"

def calculate_content_similarity(name1: str, desc1: str, feat1: str,
                                 name2: str, desc2: str, feat2: str) -> Tuple[float, str, list]:
    n1_toks = get_tokens(name1)
    n2_toks = get_tokens(name2)
    
    d1_toks = get_tokens(f"{desc1} {feat1 or ''}")
    d2_toks = get_tokens(f"{desc2} {feat2 or ''}")
    
    # Title token match
    title_overlap = n1_toks.intersection(n2_toks)
    all_overlap = (n1_toks | d1_toks).intersection(n2_toks | d2_toks)
    
    title_score = token_similarity(n1_toks, n2_toks)
    desc_score = token_similarity(d1_toks, d2_toks)
    
    combined_score = (title_score * 0.5) + (desc_score * 0.5)
    
    # Boost if high value keywords match (e.g., brand or model name)
    if title_overlap:
        combined_score = max(combined_score, 0.6 + (0.4 * title_score))
        explanation = f"Matching item keywords in title/description: {', '.join(sorted(all_overlap))}"
    elif all_overlap:
        combined_score = max(combined_score, 0.4 + (0.4 * desc_score))
        explanation = f"Shared descriptive keywords: {', '.join(sorted(all_overlap))}"
    else:
        explanation = "Few common descriptive keywords"
        
    return min(1.0, combined_score), explanation, sorted(list(all_overlap))

def calculate_match(lost_item: Dict[str, Any], found_item: Dict[str, Any]) -> Dict[str, Any]:
    """
    Computes a deterministic match score (0-100%) between a lost item report
    and a found item report based on category, location, date proximity, and textual similarity.
    """
    # 1. Category (30% weight)
    cat_score, cat_exp = calculate_category_score(
        lost_item.get('category', ''),
        found_item.get('category', '')
    )
    
    # 2. Location (25% weight)
    loc_score, loc_exp, loc_shared = calculate_location_score(
        lost_item.get('location', ''),
        found_item.get('location', '')
    )
    
    # 3. Content: Name & Description & Distinguishing Features (30% weight)
    content_score, content_exp, shared_words = calculate_content_similarity(
        lost_item.get('item_name', ''),
        lost_item.get('description', ''),
        lost_item.get('distinguishing_features', ''),
        found_item.get('item_name', ''),
        found_item.get('description', ''),
        found_item.get('distinguishing_features', '')
    )
    
    # 4. Date Proximity (15% weight)
    date_score, date_exp = calculate_date_score(
        lost_item.get('date_occurred', ''),
        found_item.get('date_occurred', '')
    )
    
    # Weighted calculation
    raw_total = (cat_score * 30.0) + (loc_score * 25.0) + (content_score * 30.0) + (date_score * 15.0)
    final_score = int(round(min(100.0, max(0.0, raw_total))))
    
    # Assign confidence tiers
    if final_score >= 80:
        confidence = "High"
    elif final_score >= 50:
        confidence = "Moderate"
    elif final_score >= 30:
        confidence = "Low"
    else:
        confidence = "Unlikely"
        
    explanations = [
        f"Category: {cat_exp} (Score: {int(cat_score * 30)}/30 pts)",
        f"Location: {loc_exp} (Score: {int(loc_score * 25)}/25 pts)",
        f"Text & Distinctions: {content_exp} (Score: {int(content_score * 30)}/30 pts)",
        f"Timeline: {date_exp} (Score: {int(date_score * 15)}/15 pts)",
    ]
    
    return {
        "score": final_score,
        "confidence": confidence,
        "breakdown": {
            "category_points": round(cat_score * 30, 1),
            "location_points": round(loc_score * 25, 1),
            "content_points": round(content_score * 30, 1),
            "date_points": round(date_score * 15, 1),
            "total_points": final_score
        },
        "explanations": explanations,
        "shared_keywords": shared_words
    }

def find_matches_for_report(target_report: Dict[str, Any], candidate_reports: List[Dict[str, Any]], min_score: int = 30) -> List[Dict[str, Any]]:
    matches = []
    for cand in candidate_reports:
        # Don't match with self or same report type
        if cand.get('id') == target_report.get('id'):
            continue
        if cand.get('report_type') == target_report.get('report_type'):
            continue
            
        lost = target_report if target_report.get('report_type') == 'lost' else cand
        found = cand if target_report.get('report_type') == 'lost' else target_report
        
        match_data = calculate_match(lost, found)
        if match_data['score'] >= min_score:
            matches.append({
                "candidate": cand,
                "score": match_data['score'],
                "confidence": match_data['confidence'],
                "breakdown": match_data['breakdown'],
                "explanations": match_data['explanations'],
                "shared_keywords": match_data['shared_keywords']
            })
            
    matches.sort(key=lambda x: x['score'], reverse=True)
    return matches
