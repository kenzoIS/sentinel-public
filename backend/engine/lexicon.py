# =============================================================
# SENTINEL — Keyword Lexicon & Red Flag Patterns
# =============================================================

URGENCY_TRIGGERS = {
    "send your atm":1.00,"atm card number":1.00,"atm pin":1.00,"enter your mpin":0.97,"send your mpin":0.97,
    "enter your otp":0.95,"send the otp":0.95,"share your otp":0.95,"enter otp here":0.95,"otp to us":0.95,
    "card number":0.93,"cvv":0.93,"bank account number":0.92,"account number and pin":0.95,
    "account suspended":0.92,"account will be suspended":0.92,"account has been limited":0.90,"permanently closed":0.90,
    "account will be closed":0.90,"account will be locked":0.88,"will be deactivated":0.87,"will be terminated":0.87,
    "will be disconnected":0.85,"will be blocked":0.85,"unauthorized transaction":0.88,"unauthorized access":0.85,
    "unauthorized login":0.85,"suspicious activity":0.80,"account compromised":0.88,"account has been flagged":0.83,
    "verify immediately":0.88,"verify now":0.85,"click here immediately":0.87,"tap here to confirm":0.83,"click to confirm":0.83,
    "update now":0.80,"update your billing":0.82,"update your information":0.78,"confirm your identity":0.78,"act within":0.80,"act now":0.75,
    "within 24 hours":0.82,"within 12 hours":0.84,"within 1 hour":0.87,"expires today":0.80,"expires soon":0.72,"today at":0.70,"effective immediately":0.75,"last warning":0.78,
    "processing fee":0.85,"pay the fee":0.83,"insurance fee":0.82,"activation fee":0.82,"shipping fee":0.75,"customs fee":0.78,
    "you have won":0.88,"claim your prize":0.88,"you are the lucky winner":0.90,"free load":0.75,"free credits":0.72,"cash assistance":0.65,
    "loan approved":0.78,"loan has been approved":0.82,"pre-approved":0.72,"0% interest":0.75,"no collateral":0.78,"tax refund":0.75,"cash release":0.80,
    "reply with your full name":0.88,"send your full name":0.85,"personal information":0.80,"id photo":0.82,"id number":0.78,"home address":0.75,
    "mpin":0.90,"otp":0.82,"gcash":0.60,"pagibig":0.58,"4ps":0.65,"congratulations":0.55,"selected":0.52,"randomly selected":0.65,
    "urgent":0.60,"important notice":0.58,"work from home":0.58,"no experience needed":0.62,"earn per month":0.60,"not you":0.65,"if this was not you":0.72,
}

IMPERSONATION_TARGETS = {
    "bdo":"Banking","bpi":"Banking","metrobank":"Banking","landbank":"Banking","pnb":"Banking","security bank":"Banking","unionbank":"Banking","rcbc":"Banking","eastwest":"Banking","bdo unibank":"Banking",
    "gcash":"E-Wallet","maya":"E-Wallet","paymaya":"E-Wallet","coins.ph":"E-Wallet","grabpay":"E-Wallet","shopee pay":"E-Wallet",
    "sss":"Government","gsis":"Government","philhealth":"Government","pagibig":"Government","pag-ibig":"Government","bir":"Government","nbi":"Government","pcso":"Government","pagcor":"Government","dswd":"Government","lto":"Government","dfa":"Government",
    "globe":"Telco","smart":"Telco","dito":"Telco","sun cellular":"Telco","tnt":"Telco",
    "lazada":"E-Commerce","shopee":"E-Commerce","zalora":"E-Commerce","tiktok shop":"E-Commerce",
    "j&t":"Logistics","jnt":"Logistics","lbc":"Logistics","flash express":"Logistics","ninjavan":"Logistics","2go":"Logistics",
    "meralco":"Utilities","maynilad":"Utilities","manila water":"Utilities","pldt":"Utilities","converge":"Utilities",
    "tonik":"Digital Bank","seabank":"Digital Bank","cimb":"Digital Bank","gotyme":"Digital Bank",
}

SUSPICIOUS_URL_PATTERNS = [
    r'bit\.ly/[^\s]+',r'tinyurl\.com/[^\s]+',r't\.co/[^\s]+',r'goo\.gl/[^\s]+',r'rb\.gy/[^\s]+',r'shorturl\.at/[^\s]+',
    r'[a-z]+-verify\.[a-z]{2,6}',r'[a-z]+-ph\.[a-z]{2,6}',r'[a-z]+-update\.[a-z]{2,6}',r'[a-z]+-secure\.[a-z]{2,6}',r'[a-z]+-confirm\.[a-z]{2,6}',r'[a-z]+-login\.[a-z]{2,6}',r'[a-z]+-claim\.[a-z]{2,6}',r'[a-z]+-online-ph\.[a-z]{2,6}',
    r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',r'(?:gcash|bdo|bpi|sss|philhealth)[^a-z][^\s]*\.[a-z]{2,6}',
]

RED_FLAG_PHRASES = [
    "click here","tap here","click the link","click now","visit now","go to","reply with","send your","call us","message us",
    "verify your","verify identity","confirm your","update your","complete verification","validate your",
    "within 24 hours","within 12 hours","within 1 hour","immediately","right now","urgent","act now","last chance","do not delay","expires today","today only",
    "will be suspended","will be terminated","will be closed","will be deactivated","will be disconnected","will be blocked","permanently","permanent suspension","account restricted",
    "never share","do not share","keep this confidential","pay the","payment required","processing fee","transfer funds","send money","bank transfer",
    "full name","home address","date of birth","mother's maiden name","account details","bank details",
]
