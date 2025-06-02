!function(){try{var t="undefined"!=typeof window?window:"undefined"!=typeof global?global:"undefined"!=typeof self?self:{},e=Error().stack;e&&(t._sentryDebugIds=t._sentryDebugIds||{},t._sentryDebugIds[e]="d242467d-185f-497e-a988-154afb3742c0",t._sentryDebugIdIdentifier="sentry-dbid-d242467d-185f-497e-a988-154afb3742c0")}catch(t){}}();"use strict";(self.webpackChunk_N_E=self.webpackChunk_N_E||[]).push([[4884],{55542:function(t,e,a){function r(t,e){t.accDescr&&e.setAccDescription?.(t.accDescr),t.accTitle&&e.setAccTitle?.(t.accTitle),t.title&&e.setDiagramTitle?.(t.title)}a.d(e,{A:function(){return r}}),(0,a(83343).eW)(r,"populateCommonDb")},74884:function(t,e,a){a.d(e,{diagram:function(){return $}});var r=a(55542),l=a(23999),o=a(56135),n=a(83343),i=a(5042),c={packet:[]},s=structuredClone(c),d=n.vZ.packet,k=(0,n.eW)(()=>{let t=(0,l.Rb)({...d,...(0,n.iE)().packet});return t.showBits&&(t.paddingY+=10),t},"getConfig"),b=(0,n.eW)(()=>s.packet,"getPacket"),p={pushWord:(0,n.eW)(t=>{t.length>0&&s.packet.push(t)},"pushWord"),getPacket:b,getConfig:k,clear:(0,n.eW)(()=>{(0,n.ZH)(),s=structuredClone(c)},"clear"),setAccTitle:n.GN,getAccTitle:n.eu,setDiagramTitle:n.g2,getDiagramTitle:n.Kr,getAccDescription:n.Mx,setAccDescription:n.U$},f=(0,n.eW)(t=>{(0,r.A)(t,p);let e=-1,a=[],l=1,{bitsPerRow:o}=p.getConfig();for(let{start:r,end:i,label:c}of t.blocks){if(i&&i<r)throw Error(`Packet block ${r} - ${i} is invalid. End must be greater than start.`);if(r!==e+1)throw Error(`Packet block ${r} - ${i??r} is not contiguous. It should start from ${e+1}.`);for(e=i??r,n.cM.debug(`Packet block ${r} - ${e} with label ${c}`);a.length<=o+1&&p.getPacket().length<1e4;){let[t,e]=u({start:r,end:i,label:c},l,o);if(a.push(t),t.end+1===l*o&&(p.pushWord(a),a=[],l++),!e)break;({start:r,end:i,label:c}=e)}}p.pushWord(a)},"populate"),u=(0,n.eW)((t,e,a)=>{if(void 0===t.end&&(t.end=t.start),t.start>t.end)throw Error(`Block start ${t.start} is greater than block end ${t.end}.`);return t.end+1<=e*a?[t,void 0]:[{start:t.start,end:e*a-1,label:t.label},{start:e*a,end:t.end,label:t.label}]},"getNextFittingBlock"),g={parse:(0,n.eW)(async t=>{let e=await (0,i.Qc)("packet",t);n.cM.debug(e),f(e)},"parse")},h=(0,n.eW)((t,e,a,r)=>{let l=r.db,i=l.getConfig(),{rowHeight:c,paddingY:s,bitWidth:d,bitsPerRow:k}=i,b=l.getPacket(),p=l.getDiagramTitle(),f=c+s,u=f*(b.length+1)-(p?0:c),g=d*k+2,h=(0,o.P)(e);for(let[t,e]of(h.attr("viewbox",`0 0 ${g} ${u}`),(0,n.v2)(h,u,g,i.useMaxWidth),b.entries()))y(h,e,t,i);h.append("text").text(p).attr("x",g/2).attr("y",u-f/2).attr("dominant-baseline","middle").attr("text-anchor","middle").attr("class","packetTitle")},"draw"),y=(0,n.eW)((t,e,a,{rowHeight:r,paddingX:l,paddingY:o,bitWidth:n,bitsPerRow:i,showBits:c})=>{let s=t.append("g"),d=a*(r+o)+o;for(let t of e){let e=t.start%i*n+1,a=(t.end-t.start+1)*n-l;if(s.append("rect").attr("x",e).attr("y",d).attr("width",a).attr("height",r).attr("class","packetBlock"),s.append("text").attr("x",e+a/2).attr("y",d+r/2).attr("class","packetLabel").attr("dominant-baseline","middle").attr("text-anchor","middle").text(t.label),!c)continue;let o=t.end===t.start,k=d-2;s.append("text").attr("x",e+(o?a/2:0)).attr("y",k).attr("class","packetByte start").attr("dominant-baseline","auto").attr("text-anchor",o?"middle":"start").text(t.start),o||s.append("text").attr("x",e+a).attr("y",k).attr("class","packetByte end").attr("dominant-baseline","auto").attr("text-anchor","end").text(t.end)}},"drawWord"),x={byteFontSize:"10px",startByteColor:"black",endByteColor:"black",labelColor:"black",labelFontSize:"12px",titleColor:"black",titleFontSize:"14px",blockStrokeColor:"black",blockStrokeWidth:"1",blockFillColor:"#efefef"},$={parser:g,db:p,renderer:{draw:h},styles:(0,n.eW)(({packet:t}={})=>{let e=(0,l.Rb)(x,t);return`
	.packetByte {
		font-size: ${e.byteFontSize};
	}
	.packetByte.start {
		fill: ${e.startByteColor};
	}
	.packetByte.end {
		fill: ${e.endByteColor};
	}
	.packetLabel {
		fill: ${e.labelColor};
		font-size: ${e.labelFontSize};
	}
	.packetTitle {
		fill: ${e.titleColor};
		font-size: ${e.titleFontSize};
	}
	.packetBlock {
		stroke: ${e.blockStrokeColor};
		stroke-width: ${e.blockStrokeWidth};
		fill: ${e.blockFillColor};
	}
	`},"styles")}}}]);