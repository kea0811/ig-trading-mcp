/**
 * Calculate Supertrend indicator
 */

function calculateATR(data, period) {
  const atr = [];
  
  for (let i = 0; i < data.length; i++) {
    if (i === 0) {
      atr.push(data[i].h - data[i].l);
    } else if (i < period) {
      const tr = Math.max(
        data[i].h - data[i].l,
        Math.abs(data[i].h - data[i - 1].c),
        Math.abs(data[i].l - data[i - 1].c)
      );
      atr.push(tr);
    } else {
      const tr = Math.max(
        data[i].h - data[i].l,
        Math.abs(data[i].h - data[i - 1].c),
        Math.abs(data[i].l - data[i - 1].c)
      );
      atr.push((atr[i - 1] * (period - 1) + tr) / period);
    }
  }
  
  return atr;
}

function calculateSupertrend(data, period = 10, multiplier = 3) {
  if (!data || data.length < period) {
    return [];
  }
  
  const atr = calculateATR(data, period);
  const supertrend = [];
  const trend = [];
  
  for (let i = 0; i < data.length; i++) {
    if (i < period - 1) {
      supertrend.push(null);
      trend.push(1);
    } else {
      const hl2 = (data[i].h + data[i].l) / 2;
      const upperBand = hl2 + multiplier * atr[i];
      const lowerBand = hl2 - multiplier * atr[i];
      
      if (i === period - 1) {
        if (data[i].c <= upperBand) {
          supertrend.push(upperBand);
          trend.push(-1);
        } else {
          supertrend.push(lowerBand);
          trend.push(1);
        }
      } else {
        if (trend[i - 1] === 1) {
          if (data[i].c <= lowerBand) {
            supertrend.push(upperBand);
            trend.push(-1);
          } else {
            supertrend.push(Math.max(lowerBand, supertrend[i - 1]));
            trend.push(1);
          }
        } else {
          if (data[i].c >= upperBand) {
            supertrend.push(lowerBand);
            trend.push(1);
          } else {
            supertrend.push(Math.min(upperBand, supertrend[i - 1]));
            trend.push(-1);
          }
        }
      }
    }
  }
  
  return supertrend;
}

module.exports = { calculateSupertrend, calculateATR };