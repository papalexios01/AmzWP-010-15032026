/**
 * ============================================================================
 * AI Copywriter Utility v1.0
 * ============================================================================
 * AI-powered copy enhancement for maximum conversions:
 * - Compelling verdict generation
 * - Benefit-focused bullet points
 * - Urgency hooks and CTAs
 * - FAQ objection handling
 * ============================================================================
 */

import { ProductDetails, AppConfig } from '../types';

export interface EnhancedCopy {
  verdict: string;
  headline: string;
  bulletPoints: string[];
  callToAction: string;
  faqs: { question: string; answer: string }[];
  urgencyHook: string;
}

const COPY_ENHANCEMENT_PROMPT = `You are an elite conversion copywriter specializing in Amazon affiliate content.

PRODUCT DATA:
- Name: {{PRODUCT_NAME}}
- Brand: {{BRAND}}
- Category: {{CATEGORY}}
- Price: {{PRICE}}
- Rating: {{RATING}}/5 ({{REVIEW_COUNT}} reviews)
- Prime: {{PRIME}}

CURRENT POST CONTEXT:
{{CONTEXT}}

Generate HIGHLY PERSUASIVE, conversion-optimized copy for this product:

1. VERDICT (2-3 sentences): A compelling expert opinion that establishes authority and creates desire. Start with the benefit, not the product. Use power words like "transforms", "eliminates", "delivers".

2. HEADLINE (10 words max): An attention-grabbing headline that creates curiosity or urgency.

3. BULLET_POINTS (4 points): Each must start with a BENEFIT (what user gains), then feature. Use ✓ format. Be specific with numbers when possible.

4. CALL_TO_ACTION (5 words max): Urgency-driven CTA that goes beyond "Buy Now". Examples: "Claim Your Discount Today", "See Why 50K+ Chose This".

5. FAQS (3 questions): Real objection-handling questions buyers have. Answers should be 1-2 sentences max and remove purchasing friction.

6. URGENCY_HOOK (1 sentence): A scarcity or time-limited message that's believable.

RULES:
- NO generic phrases like "high quality" or "great product"
- Use numbers and specifics wherever possible
- Address the reader as "you" 
- Focus on TRANSFORMATION and OUTCOME, not features
- Match the tone to the product category (tech = precise, kitchen = warm, fitness = motivational)

Return ONLY valid JSON:
{
  "verdict": "...",
  "headline": "...",
  "bulletPoints": ["...", "...", "...", "..."],
  "callToAction": "...",
  "faqs": [{"question": "...", "answer": "..."}, {"question": "...", "answer": "..."}, {"question": "...", "answer": "..."}],
  "urgencyHook": "..."
}`;

const extractJSON = (text: string): string => {
  const jsonMatch = text.match(/\{[\s\S]*\}/);
  return jsonMatch ? jsonMatch[0] : '{}';
};

export const enhanceProductCopy = async (
  product: ProductDetails,
  postContext: string,
  config: AppConfig,
  callAIProvider: (config: AppConfig, systemPrompt: string, userPrompt: string) => Promise<{ text: string }>
): Promise<EnhancedCopy> => {
  const prompt = COPY_ENHANCEMENT_PROMPT
    .replace('{{PRODUCT_NAME}}', product.title || 'Unknown Product')
    .replace('{{BRAND}}', product.brand || 'Unknown')
    .replace('{{CATEGORY}}', product.category || 'General')
    .replace('{{PRICE}}', product.price || '$0.00')
    .replace('{{RATING}}', String(product.rating || 4.5))
    .replace('{{REVIEW_COUNT}}', String(product.reviewCount || 1000))
    .replace('{{PRIME}}', product.prime ? 'Yes' : 'No')
    .replace('{{CONTEXT}}', postContext.substring(0, 2000));

  try {
    const response = await callAIProvider(
      config, 
      'You are a conversion copywriter. Return only valid JSON.',
      prompt
    );

    const jsonStr = extractJSON(response.text);
    const parsed = JSON.parse(jsonStr);
    
    return {
      verdict: parsed.verdict || product.verdict || '',
      headline: parsed.headline || product.title || '',
      bulletPoints: Array.isArray(parsed.bulletPoints) 
        ? parsed.bulletPoints 
        : (product.evidenceClaims || []),
      callToAction: parsed.callToAction || 'Check Price on Amazon',
      faqs: Array.isArray(parsed.faqs) 
        ? parsed.faqs 
        : (product.faqs || []),
      urgencyHook: parsed.urgencyHook || '',
    };
  } catch {
    return {
      verdict: product.verdict || '',
      headline: product.title || '',
      bulletPoints: product.evidenceClaims || [],
      callToAction: 'Check Price on Amazon',
      faqs: product.faqs || [],
      urgencyHook: '',
    };
  }
};

export const generateQuickHeadlines = (productTitle: string, category?: string): string[] => {
  const templates = [
    `Why ${productTitle} Is a Game-Changer`,
    `The Truth About ${productTitle}`,
    `${productTitle}: Worth Every Penny?`,
    `Is ${productTitle} Right for You?`,
    `What Nobody Tells You About ${productTitle}`,
  ];
  return templates;
};

export const generatePowerWords = (): string[] => [
  'transforms', 'eliminates', 'delivers', 'guarantees', 'unlocks',
  'supercharges', 'revolutionizes', 'maximizes', 'accelerates', 'amplifies'
];

export default enhanceProductCopy;
