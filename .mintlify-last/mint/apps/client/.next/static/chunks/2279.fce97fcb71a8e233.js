!function(){try{var e="undefined"!=typeof window?window:"undefined"!=typeof global?global:"undefined"!=typeof self?self:{},t=Error().stack;t&&(e._sentryDebugIds=e._sentryDebugIds||{},e._sentryDebugIds[t]="5028cb74-ddec-4557-a430-abfee22dd541",e._sentryDebugIdIdentifier="sentry-dbid-5028cb74-ddec-4557-a430-abfee22dd541")}catch(e){}}();"use strict";(self.webpackChunk_N_E=self.webpackChunk_N_E||[]).push([[2279],{55542:function(e,t,i){function a(e,t){e.accDescr&&t.setAccDescription?.(e.accDescr),e.accTitle&&t.setAccTitle?.(e.accTitle),e.title&&t.setDiagramTitle?.(e.title)}i.d(t,{A:function(){return a}}),(0,i(83343).eW)(a,"populateCommonDb")},22279:function(e,t,i){i.d(t,{diagram:function(){return C}});var a=i(55542),r=i(23999),l=i(56135),n=i(83343),s=i(5042),o=i(85008),c=n.vZ.pie,d={sections:new Map,showData:!1,config:c},p=d.sections,u=d.showData,f=structuredClone(c),g=(0,n.eW)(()=>structuredClone(f),"getConfig"),h=(0,n.eW)(()=>{p=new Map,u=d.showData,(0,n.ZH)()},"clear"),y=(0,n.eW)(({label:e,value:t})=>{p.has(e)||(p.set(e,t),n.cM.debug(`added new section: ${e}, with value: ${t}`))},"addSection"),w=(0,n.eW)(()=>p,"getSections"),x=(0,n.eW)(e=>{u=e},"setShowData"),m=(0,n.eW)(()=>u,"getShowData"),b={getConfig:g,clear:h,setDiagramTitle:n.g2,getDiagramTitle:n.Kr,setAccTitle:n.GN,getAccTitle:n.eu,setAccDescription:n.U$,getAccDescription:n.Mx,addSection:y,getSections:w,setShowData:x,getShowData:m},D=(0,n.eW)((e,t)=>{(0,a.A)(e,t),t.setShowData(e.showData),e.sections.map(t.addSection)},"populateDb"),S={parse:(0,n.eW)(async e=>{let t=await (0,s.Qc)("pie",e);n.cM.debug(t),D(t,b)},"parse")},T=(0,n.eW)(e=>`
  .pieCircle{
    stroke: ${e.pieStrokeColor};
    stroke-width : ${e.pieStrokeWidth};
    opacity : ${e.pieOpacity};
  }
  .pieOuterCircle{
    stroke: ${e.pieOuterStrokeColor};
    stroke-width: ${e.pieOuterStrokeWidth};
    fill: none;
  }
  .pieTitleText {
    text-anchor: middle;
    font-size: ${e.pieTitleTextSize};
    fill: ${e.pieTitleTextColor};
    font-family: ${e.fontFamily};
  }
  .slice {
    font-family: ${e.fontFamily};
    fill: ${e.pieSectionTextColor};
    font-size:${e.pieSectionTextSize};
    // fill: white;
  }
  .legend text {
    fill: ${e.pieLegendTextColor};
    font-family: ${e.fontFamily};
    font-size: ${e.pieLegendTextSize};
  }
`,"getStyles"),$=(0,n.eW)(e=>{let t=[...e.entries()].map(e=>({label:e[0],value:e[1]})).sort((e,t)=>t.value-e.value);return(0,o.ve8)().value(e=>e.value)(t)},"createPieArcs"),C={parser:S,db:b,renderer:{draw:(0,n.eW)((e,t,i,a)=>{n.cM.debug("rendering pie chart\n"+e);let s=a.db,c=(0,n.nV)(),d=(0,r.Rb)(s.getConfig(),c.pie),p=(0,l.P)(t),u=p.append("g");u.attr("transform","translate(225,225)");let{themeVariables:f}=c,[g]=(0,r.VG)(f.pieOuterStrokeWidth);g??=2;let h=d.textPosition,y=(0,o.Nb1)().innerRadius(0).outerRadius(185),w=(0,o.Nb1)().innerRadius(185*h).outerRadius(185*h);u.append("circle").attr("cx",0).attr("cy",0).attr("r",185+g/2).attr("class","pieOuterCircle");let x=s.getSections(),m=$(x),b=[f.pie1,f.pie2,f.pie3,f.pie4,f.pie5,f.pie6,f.pie7,f.pie8,f.pie9,f.pie10,f.pie11,f.pie12],D=(0,o.PKp)(b);u.selectAll("mySlices").data(m).enter().append("path").attr("d",y).attr("fill",e=>D(e.data.label)).attr("class","pieCircle");let S=0;x.forEach(e=>{S+=e}),u.selectAll("mySlices").data(m).enter().append("text").text(e=>(e.data.value/S*100).toFixed(0)+"%").attr("transform",e=>"translate("+w.centroid(e)+")").style("text-anchor","middle").attr("class","slice"),u.append("text").text(s.getDiagramTitle()).attr("x",0).attr("y",-200).attr("class","pieTitleText");let T=u.selectAll(".legend").data(D.domain()).enter().append("g").attr("class","legend").attr("transform",(e,t)=>"translate(216,"+(22*t-22*D.domain().length/2)+")");T.append("rect").attr("width",18).attr("height",18).style("fill",D).style("stroke",D),T.data(m).append("text").attr("x",22).attr("y",14).text(e=>{let{label:t,value:i}=e.data;return s.getShowData()?`${t} [${i}]`:t});let C=512+Math.max(...T.selectAll("text").nodes().map(e=>e?.getBoundingClientRect().width??0));p.attr("viewBox",`0 0 ${C} 450`),(0,n.v2)(p,450,C,d.useMaxWidth)},"draw")},styles:T}}}]);