<?php
// includes/bot_detection.php

class BotDetection {
    // Lista de User-Agents de bots conocidos
    private $bots = [
   $bots = [
    // Google
    'Googlebot',
    'Googlebot-Image',
    'Googlebot-News',
    'Googlebot-Video',
    'Mediapartners-Google', // Google Ads
    'AdsBot-Google', // Google Ads
    'AdsBot-Google-Mobile', // Google Ads (móvil)
    'AdsBot-Google-Mobile-Apps', // Google Ads (apps móviles)

    // Bing
    'Bingbot',
    'AdIdxBot', // Bing Ads
    'BingPreview',

    // Yandex
    'YandexBot',
    'YandexImages',
    'YandexVideo',
    'YandexMedia',
    'YandexMetrika', // Yandex Metrica (analytics)

    // Baidu
    'Baiduspider',
    'Baiduspider-image',
    'Baiduspider-video',

    // DuckDuckGo
    'DuckDuckBot',

    // Yahoo
    'Slurp', // Yahoo Slurp

    // Ahrefs (SEO)
    'AhrefsBot',

    // Majestic (SEO)
    'MJ12bot',

    // Semrush (SEO)
    'SemrushBot',

    // Alexa (Amazon)
    'ia_archiver',

    // Apple
    'Applebot',

    // Facebook
    'facebookexternalhit',

    // Twitter
    'Twitterbot',

    // LinkedIn
    'LinkedInBot',

    // Pinterest
    'Pinterestbot',

    // WhatsApp
    'WhatsApp',

    // MSN (Microsoft)
    'msnbot',

    // Seznam (buscador checo)
    'SeznamBot',

    // Sogou (buscador chino)
    'Sogou web spider',

    // Exabot (Exalead)
    'Exabot',

    // DotBot (DotNetDotCom)
    'DotBot',

    // Common Crawl
    'CCBot',

    // Apache Nutch
    'Nutch',

    // BLEXBot
    'BLEXBot',

    // Qwant (buscador francés)
    'Qwantify',

    // ZoomInfo
    'ZoominfoBot',

    // SiteChecker
    'SiteCheckerBotCrawler',

    // PetalBot (Huawei)
    'PetalBot',

    // Otros
    'BLEXBot',
    'Qwantify',
    'ZoominfoBot',
    'SiteCheckerBotCrawler'
];
    

    // Función para detectar si el visitante es un bot
    public function es_bot() {
        $user_agent = $_SERVER['HTTP_USER_AGENT'];

        // Verificar si el User-Agent coincide con algún bot conocido
        foreach ($this->bots as $bot) {
            if (stripos($user_agent, $bot) !== false) {
                return true; // Es un bot
            }
        }

        // Verificar otros indicadores de bots
        if (empty($user_agent)) {
            return true; // Sin User-Agent, probablemente sea un bot
        }

        if ($this->es_head_request()) {
            return true; // Solicitud HEAD, probablemente sea un bot
        }

        return false; // No es un bot
    }

    // Función para detectar solicitudes HEAD (usadas por bots)
    private function es_head_request() {
        return $_SERVER['REQUEST_METHOD'] === 'HEAD';
    }
}
?>