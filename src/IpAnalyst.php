<?php

namespace jinyicheng\IpAnalyst;

use Exception;
use InvalidArgumentException;

class IpAnalyst
{
    private $file = NULL;
    private $fileSize = 0;
    private $nodeCount = 0;
    private $nodeOffset = 0;

    private $meta = [];

    private $database = 'src/data.ia';

    private static $reader = null;

    private static $cached = [];


    /**
     * 查询 IP 信息
     *
     * @param $ip
     * @return mixed|string
     */
    public static function search($ip)
    {
        if (empty($ip) === true) return 'N/A';

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6) === FALSE) {
            throw new InvalidArgumentException("The value \"$ip\" is not a valid IP address.");
        }

        $host = gethostbyname($ip);

        if (isset(self::$cached[$host]) === true) return self::$cached[$host];

        try {
            $reader = self::init();
            $node = $reader->findNode($ip);

            if ($node > 0) {
                $data = $reader->resolve($node);
                $values = explode("\t", $data);
                $location = array_slice($values, $reader->meta['languages']['CN'], count($reader->meta['fields']));
                $location[] = '';
                $locationCode = self::getLocationCode($location);
                $location[] = $locationCode;
                self::$cached[$host] = $location;
                return self::$cached[$host];
            }
        } catch (Exception $e) {
            return $e->getMessage();
        }
        return [];
    }


    /**
     * @param $ip
     * @return int|mixed
     * @throws Exception
     */
    private function findNode($ip)
    {
        static $v4offset = 0;
        static $v6offsetCache = [];

        $binary = inet_pton($ip);
        $bitCount = strlen($binary) * 8; // 32 | 128
        $key = substr($binary, 0, 2);
        $node = 0;
        $index = 0;
        if ($bitCount === 32) {
            if ($v4offset === 0) {
                for ($i = 0; $i < 96 && $node < $this->nodeCount; $i++) {
                    $idx = ($i >= 80) ? 1 : 0;
                    $node = $this->readNode($node, $idx);
                    if ($node > $this->nodeCount) return 0;
                }
                $v4offset = $node;
            } else {
                $node = $v4offset;
            }
        } else {
            if (isset($v6offsetCache[$key])) {
                $index = 16;
                $node = $v6offsetCache[$key];
            }
        }

        for ($i = $index; $i < $bitCount; $i++) {
            if ($node >= $this->nodeCount) break;

            $node = $this->readNode($node, 1 & ((0xFF & ord($binary[$i >> 3])) >> 7 - ($i % 8)));

            if ($i == 15) $v6offsetCache[$key] = $node;
        }

        if ($node === $this->nodeCount) {
            return 0;
        } elseif ($node > $this->nodeCount) {
            return $node;
        }


        throw new Exception("find node failed");
    }


    /**
     * @param $node
     * @param $index
     * @return mixed
     * @throws Exception
     */
    private function readNode($node, $index)
    {
        return unpack('N', $this->read($this->file, $node * 8 + $index * 4, 4))[1];
    }


    /**
     * @param $node
     * @return mixed
     * @throws Exception
     */
    private function resolve($node)
    {
        $resolved = $node - $this->nodeCount + $this->nodeCount * 8;
        if ($resolved >= $this->fileSize) {
            return NULL;
        }

        $bytes = $this->read($this->file, $resolved, 2);
        $size = unpack('N', str_pad($bytes, 4, "\x00", STR_PAD_LEFT))[1];

        $resolved += 2;

        return $this->read($this->file, $resolved, $size);
    }

    /**
     * @param $stream
     * @param $offset
     * @param $length
     * @return bool|string
     * @throws Exception
     */
    private function read($stream, $offset, $length)
    {
        if ($length > 0) {
            if (fseek($stream, $offset + $this->nodeOffset) === 0) {
                $value = fread($stream, $length);
                if (strlen($value) === $length) {
                    return $value;
                }
            }

            throw new Exception("The Database file read bad data");
        }

        return '';
    }

    /**
     * 初始化单例
     *
     * @return IpAnalyst|null |null
     * @throws Exception
     */
    private static function init()
    {
        if (!is_null(self::$reader)) {
            return self::$reader;
        } else {
            $reader = new self();
            $databaseSrc = __DIR__ . '/ip/' . $reader->database;
            if (is_readable($databaseSrc) === FALSE) {
                throw new InvalidArgumentException("The IP Database file \"{$databaseSrc}\" does not exist or is not readable.");
            }
            $reader->file = @fopen($databaseSrc, 'rb');
            if ($reader->file === FALSE) {
                throw new InvalidArgumentException("IP Database File opening \"{$databaseSrc}\".");
            }
            $reader->fileSize = @filesize($databaseSrc);
            if ($reader->fileSize === FALSE) {
                throw new UnexpectedValueException("Error determining the size of \"{$databaseSrc}\".");
            }

            $metaLength = unpack('N', fread($reader->file, 4))[1];
            $text = fread($reader->file, $metaLength);

            $reader->meta = (array)json_decode($text, true);

            if (!isset($reader->meta['fields']) || !isset($reader->meta['languages'])) {
                throw new Exception('IP Database metadata error.');
            }

            $fileSize = 4 + $metaLength + $reader->meta['total_size'];
            if ($fileSize != $reader->fileSize) {
                throw  new Exception('IP Database size error.');
            }

            $reader->nodeCount = $reader->meta['node_count'];
            $reader->nodeOffset = 4 + $metaLength;

            self::$reader = $reader;

            return $reader;
        }
    }

    /**
     * 获取城市的行政区划编码
     *
     * @param $arr
     * @return string
     */
    private static function getLocationCode($arr)
    {
        $province = $arr[1];
        $city = $arr[2];
        $locationCode = self::locations();
        $code = "";
        if (!isset($locationCode[$province])) {
            return $code;
        }
        $code = $locationCode[$province]["code"];
        if (!empty($city)) {
            foreach ($locationCode[$province]["cities"] as $key => $loc) {
                if (strpos($key, $city) !== false) {
                    $code = $loc;
                    break;
                }
            }
        }

        return $code;
    }

    /**
     * 城市的行政区划信息
     *
     * @return array
     */
    public static function locations()
    {
        $locationCode = [];
        $locationCode["北京"] = [
            "code" => "110000",
            "cities" => []
        ];
        $locationCode["天津"] = [
            "code" => "120000",
            "cities" => []
        ];
        $locationCode["河北"] = [
            "code" => "130000",
            "cities" => ["石家庄" => "130100", "唐山" => "130200", "秦皇岛" => "130300", "邯郸" => "130400", "邢台" => "130500", "保定" => "130600", "张家口" => "130700", "承德" => "130800", "沧州" => "130900", "廊坊" => "131000", "衡水" => "131100"]
        ];
        $locationCode["山西"] = [
            "code" => "140000",
            "cities" => ["太原" => "140100", "大同" => "140200", "阳泉" => "140300", "长治" => "140400", "晋城" => "140500", "朔州" => "140600", "晋中" => "140700", "运城" => "140800", "忻州" => "140900", "临汾" => "141000", "吕梁" => "141100"]
        ];
        $locationCode["内蒙古"] = [
            "code" => "150000",
            "cities" => ["呼和浩特" => "150100", "包头" => "150200", "乌海" => "150300", "赤峰" => "150400", "通辽" => "150500", "鄂尔多斯" => "150600", "呼伦贝尔" => "150700", "巴彦淖尔" => "150800", "乌兰察布" => "150900", "兴安盟" => "152200", "锡林郭勒盟" => "152500", "阿拉善盟" => "152900"]
        ];
        $locationCode["辽宁"] = [
            "code" => "210000",
            "cities" => ["沈阳" => "210100", "大连" => "210200", "鞍山" => "210300", "抚顺" => "210400", "本溪" => "210500", "丹东" => "210600", "锦州" => "210700", "营口" => "210800", "阜新" => "210900", "辽阳" => "211000", "盘锦" => "211100", "铁岭" => "211200", "朝阳" => "211300", "葫芦岛" => "211400"]
        ];
        $locationCode["吉林"] = [
            "code" => "220000",
            "cities" => ["长春" => "220100", "吉林" => "220200", "四平" => "220300", "辽源" => "220400", "通化" => "220500", "白山" => "220600", "松原" => "220700", "白城" => "220800", "延边朝鲜族自治州" => "222400"]
        ];
        $locationCode["黑龙江"] = [
            "code" => "230000",
            "cities" => ["哈尔滨" => "230100", "齐齐哈尔" => "230200", "鸡西" => "230300", "鹤岗" => "230400", "双鸭山" => "230500", "大庆" => "230600", "伊春" => "230700", "佳木斯" => "230800", "七台河" => "230900", "牡丹江" => "231000", "黑河" => "231100", "绥化" => "231200", "大兴安岭地区" => "232700"]
        ];
        $locationCode["上海"] = [
            "code" => "310000",
            "cities" => []
        ];
        $locationCode["江苏"] = [
            "code" => "320000",
            "cities" => ["南京" => "320100", "无锡" => "320200", "徐州" => "320300", "常州" => "320400", "苏州" => "320500", "南通" => "320600", "连云港" => "320700", "淮安" => "320800", "盐城" => "320900", "扬州" => "321000", "镇江" => "321100", "泰州" => "321200", "宿迁" => "321300"]
        ];
        $locationCode["浙江"] = [
            "code" => "330000",
            "cities" => ["杭州" => "330100", "宁波" => "330200", "温州" => "330300", "嘉兴" => "330400", "湖州" => "330500", "绍兴" => "330600", "金华" => "330700", "衢州" => "330800", "舟山" => "330900", "台州" => "331000", "丽水" => "331100"]
        ];
        $locationCode["安徽"] = [
            "code" => "340000",
            "cities" => ["合肥" => "340100", "芜湖" => "340200", "蚌埠" => "340300", "淮南" => "340400", "马鞍山" => "340500", "淮北" => "340600", "铜陵" => "340700", "安庆" => "340800", "黄山" => "341000", "滁州" => "341100", "阜阳" => "341200", "宿州" => "341300", "巢湖" => "341400", "六安" => "341500", "亳州" => "341600", "池州" => "341700", "宣城" => "341800"]
        ];
        $locationCode["福建"] = [
            "code" => "350000",
            "cities" => ["福州" => "350100", "厦门" => "350200", "莆田" => "350300", "三明" => "350400", "泉州" => "350500", "漳州" => "350600", "南平" => "350700", "龙岩" => "350800", "宁德" => "350900"]
        ];
        $locationCode["江西"] = [
            "code" => "360000",
            "cities" => ["南昌" => "360100", "景德镇" => "360200", "萍乡" => "360300", "九江" => "360400", "新余" => "360500", "鹰潭" => "360600", "赣州" => "360700", "吉安" => "360800", "宜春" => "360900", "抚州" => "361000", "上饶" => "361100"]
        ];
        $locationCode["山东"] = [
            "code" => "370000",
            "cities" => ["济南" => "370100", "青岛" => "370200", "淄博" => "370300", "枣庄" => "370400", "东营" => "370500", "烟台" => "370600", "潍坊" => "370700", "济宁" => "370800", "泰安" => "370900", "威海" => "371000", "日照" => "371100", "莱芜" => "371200", "临沂" => "371300", "德州" => "371400", "聊城" => "371500", "滨州" => "371600", "菏泽" => "371700"]
        ];
        $locationCode["河南"] = [
            "code" => "410000",
            "cities" => ["郑州" => "410100", "开封" => "410200", "洛阳" => "410300", "平顶山" => "410400", "安阳" => "410500", "鹤壁" => "410600", "新乡" => "410700", "焦作" => "410800", "濮阳" => "410900", "许昌" => "411000", "漯河" => "411100", "三门峡" => "411200", "南阳" => "411300", "商丘" => "411400", "信阳" => "411500", "周口" => "411600", "驻马店" => "411700", "济源" => "419001"]
        ];
        $locationCode["湖北"] = [
            "code" => "420000",
            "cities" => ["武汉" => "420100", "黄石" => "420200", "十堰" => "420300", "宜昌" => "420500", "襄樊" => "420600", "鄂州" => "420700", "荆门" => "420800", "孝感" => "420900", "荆州" => "421000", "黄冈" => "421100", "咸宁" => "421200", "随州" => "421300", "恩施土家族苗族自治州" => "422800", "仙桃" => "429004", "潜江" => "429005", "天门" => "429006", "神农架林区" => "429021"]
        ];
        $locationCode["湖南"] = [
            "code" => "430000",
            "cities" => ["长沙" => "430100", "株洲" => "430200", "湘潭" => "430300", "衡阳" => "430400", "邵阳" => "430500", "岳阳" => "430600", "常德" => "430700", "张家界" => "430800", "益阳" => "430900", "郴州" => "431000", "永州" => "431100", "怀化" => "431200", "娄底" => "431300", "湘西土家族苗族自治州" => "433100"]
        ];
        $locationCode["广东"] = [
            "code" => "440000",
            "cities" => ["广州" => "440100", "韶关" => "440200", "深圳" => "440300", "珠海" => "440400", "汕头" => "440500", "佛山" => "440600", "江门" => "440700", "湛江" => "440800", "茂名" => "440900", "肇庆" => "441200", "惠州" => "441300", "梅州" => "441400", "汕尾" => "441500", "河源" => "441600", "阳江" => "441700", "清远" => "441800", "东莞" => "441900", "中山" => "442000", "潮州" => "445100", "揭阳" => "445200", "云浮" => "445300"]
        ];
        $locationCode["广西"] = [
            "code" => "450000",
            "cities" => ["南宁" => "450100", "柳州" => "450200", "桂林" => "450300", "梧州" => "450400", "北海" => "450500", "防城港" => "450600", "钦州" => "450700", "贵港" => "450800", "玉林" => "450900", "百色" => "451000", "贺州" => "451100", "河池" => "451200", "来宾" => "451300", "崇左" => "451400"]
        ];
        $locationCode["海南"] = [
            "code" => "460000",
            "cities" => ["海口" => "460100", "三亚" => "460200", "五指山" => "469001", "琼海" => "469002", "儋州" => "469003", "文昌" => "469005", "万宁" => "469006", "东方" => "469007", "定安县" => "469021", "屯昌县" => "469022", "澄迈县" => "469023", "临高县" => "469024", "白沙黎族自治县" => "469025", "昌江黎族自治县" => "469026", "乐东黎族自治县" => "469027", "陵水黎族自治县" => "469028", "保亭黎族苗族自治县" => "469029", "琼中黎族苗族自治县" => "469030", "西沙群岛" => "469031", "南沙群岛" => "469032", "中沙群岛的岛礁及其海域" => "469033"]
        ];
        $locationCode["重庆"] = [
            "code" => "500000",
            "cities" => [],
        ];
        $locationCode["四川"] = [
            "code" => "510000",
            "cities" => ["成都" => "510100", "自贡" => "510300", "攀枝花" => "510400", "泸州" => "510500", "德阳" => "510600", "绵阳" => "510700", "广元" => "510800", "遂宁" => "510900", "内江" => "511000", "乐山" => "511100", "南充" => "511300", "眉山" => "511400", "宜宾" => "511500", "广安" => "511600", "达州" => "511700", "雅安" => "511800", "巴中" => "511900", "资阳" => "512000", "阿坝藏族羌族自治州" => "513200", "甘孜藏族自治州" => "513300", "凉山彝族自治州" => "513400"]
        ];
        $locationCode["贵州"] = [
            "code" => "520000",
            "cities" => ["贵阳" => "520100", "六盘水" => "520200", "遵义" => "520300", "安顺" => "520400", "铜仁地区" => "522200", "黔西南布依族苗族自治州" => "522300", "毕节地区" => "522400", "黔东南苗族侗族自治州" => "522600", "黔南布依族苗族自治州" => "522700"],
        ];
        $locationCode["云南"] = [
            "code" => "530000",
            "cities" => ["昆明" => "530100", "曲靖" => "530300", "玉溪" => "530400", "保山" => "530500", "昭通" => "530600", "丽江" => "530700", "普洱" => "530800", "临沧" => "530900", "楚雄彝族自治州" => "532300", "红河哈尼族彝族自治州" => "532500", "文山壮族苗族自治州" => "532600", "西双版纳傣族自治州" => "532800", "大理白族自治州" => "532900", "德宏傣族景颇族自治州" => "533100", "怒江傈僳族自治州" => "533300", "迪庆藏族自治州" => "533400"]
        ];
        $locationCode["西藏"] = [
            "code" => "540000",
            "cities" => ["拉萨" => "540100", "昌都地区" => "542100", "山南地区" => "542200", "日喀则地区" => "542300", "那曲地区" => "542400", "阿里地区" => "542500", "林芝地区" => "542600"]
        ];
        $locationCode["陕西"] = [
            "code" => "610000",
            "cities" => ["西安" => "610100", "铜川" => "610200", "宝鸡" => "610300", "咸阳" => "610400", "渭南" => "610500", "延安" => "610600", "汉中" => "610700", "榆林" => "610800", "安康" => "610900", "商洛" => "611000"]
        ];
        $locationCode["甘肃"] = [
            "code" => "620000",
            "cities" => ["兰州" => "620100", "嘉峪关" => "620200", "金昌" => "620300", "白银" => "620400", "天水" => "620500", "武威" => "620600", "张掖" => "620700", "平凉" => "620800", "酒泉" => "620900", "庆阳" => "621000", "定西" => "621100", "陇南" => "621200", "临夏回族自治州" => "622900", "甘南藏族自治州" => "623000"]
        ];
        $locationCode["青海"] = [
            "code" => "630000",
            "cities" => ["西宁" => "630100", "海东地区" => "632100", "海北藏族自治州" => "632200", "黄南藏族自治州" => "632300", "海南藏族自治州" => "632500", "果洛藏族自治州" => "632600", "玉树藏族自治州" => "632700", "海西蒙古族藏族自治州" => "632800"]
        ];
        $locationCode["宁夏"] = [
            "code" => "640000",
            "cities" => ["银川" => "640100", "石嘴山" => "640200", "吴忠" => "640300", "固原" => "640400", "中卫" => "640500"]
        ];
        $locationCode["新疆"] = [
            "code" => "650000",
            "cities" => ["乌鲁木齐" => "650100", "克拉玛依" => "650200", "吐鲁番地区" => "652100", "哈密地区" => "652200", "昌吉回族自治州" => "652300", "博尔塔拉蒙古自治州" => "652700", "巴音郭楞蒙古自治州" => "652800", "阿克苏地区" => "652900", "克孜勒苏柯尔克孜自治州" => "653000", "喀什地区" => "653100", "和田地区" => "653200", "伊犁哈萨克自治州" => "654000", "塔城地区" => "654200", "阿勒泰地区" => "654300", "石河子" => "659001", "阿拉尔" => "659002", "图木舒克" => "659003", "五家渠" => "659004"]
        ];
        $locationCode["台湾"] = [
            "code" => "710000",
            "cities" => []
        ];
        $locationCode["香港"] = [
            "code" => "810000",
            "cities" => []
        ];
        $locationCode["澳门"] = [
            "code" => "820000",
            "cities" => []
        ];

        return $locationCode;
    }
}