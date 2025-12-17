// A minimal dictionary for common Chinese characters to Pinyin
// For a production app, use a full library like pinyin-pro
const PINYIN_MAP = {
  // Common characters (Demo subset)
  '我': 'wo3', '你': 'ni3', '他': 'ta1', '们': 'men5', '是': 'shi4',
  '的': 'de5', '了': 'le5', '不': 'bu4', '在': 'zai4', '有': 'you3',
  '个': 'ge4', '人': 'ren2', '这': 'zhe4', '大': 'da4', '中': 'zhong1',
  '国': 'guo2', '上': 'shang4', '下': 'xia4', '和': 'he2', '为': 'wei4',
  '安': 'an1', '全': 'quan2', '笔': 'bi3', '记': 'ji4', '测': 'ce4',
  '试': 'shi4', '密': 'mi4', '码': 'ma3', '系': 'xi4', '统': 'tong3',
  '零': 'ling2', '信': 'xin4', '任': 'ren4', '加': 'jia1', '解': 'jie3',
  '设': 'she4', '计': 'ji4', '学': 'xue2', '校': 'xiao4', '教': 'jiao4',
  '育': 'yu4', '软': 'ruan3', '件': 'jian4', '漏': 'lou4', '洞': 'dong4'
};

const RANDOM_CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';

export function getPinyin(char) {
  return PINYIN_MAP[char] || null;
}

export function getRandomChar() {
  return RANDOM_CHARS[Math.floor(Math.random() * RANDOM_CHARS.length)];
}
